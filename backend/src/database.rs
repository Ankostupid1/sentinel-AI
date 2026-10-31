use crate::Alert;
use serde::Serialize;
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};

#[derive(Serialize)]
pub struct AnalyticsResponse {
    pub period: String,
    pub total_alerts: i64,
    pub critical_alerts: i64,
    pub high_alerts: i64,
    pub medium_alerts: i64,
    pub low_alerts: i64,
    pub open_incidents: i64,
    pub resolved_incidents: i64,
    pub average_resolution_minutes: Option<f64>,
    pub alerts_over_time: Vec<TimeBucket>,
    pub severity_over_time: Vec<SeverityBucket>,
    pub top_sources: Vec<SourceCount>,
}

#[derive(Serialize)]
pub struct TimeBucket {
    pub timestamp: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct SeverityBucket {
    pub timestamp: String,
    pub severity: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct SourceCount {
    pub source_ip: String,
    pub count: i64,
}

pub async fn initialize_database() -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename("sentinel.db")
                .create_if_missing(true),
        )
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            distinct_ports INTEGER NOT NULL,
            time_window_seconds INTEGER NOT NULL,
            severity TEXT NOT NULL,
            created_at TEXT NOT NULL,
            ai_status TEXT NOT NULL,
            ai_assessment TEXT,
            ai_error TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            acknowledged_at TEXT,
            resolved_at TEXT,
            analyst_notes TEXT
        )
        "#,
    )
    .execute(&pool)
    .await?;

    // Migrate databases created before incident management was added.
    let columns = sqlx::query("PRAGMA table_info(alerts)")
        .fetch_all(&pool)
        .await?;

    let mut column_names = Vec::new();

    for column in columns {
        let name: String = column.try_get("name")?;
        column_names.push(name);
    }

    let migrations = [
        (
            "status",
            "ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'new'",
        ),
        (
            "acknowledged_at",
            "ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT",
        ),
        (
            "resolved_at",
            "ALTER TABLE alerts ADD COLUMN resolved_at TEXT",
        ),
        (
            "analyst_notes",
            "ALTER TABLE alerts ADD COLUMN analyst_notes TEXT",
        ),
    ];

    for (column_name, migration_sql) in migrations {
        if !column_names.iter().any(|name| name == column_name) {
            sqlx::query(migration_sql).execute(&pool).await?;
            println!("[DATABASE] Added column: {}", column_name);
        }
    }

    println!("[DATABASE] SQLite database initialized");

    Ok(pool)
}

pub async fn save_alert(pool: &SqlitePool, alert: &Alert) -> Result<(), sqlx::Error> {
    let assessment = alert
        .ai_assessment
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;

    sqlx::query(
        r#"
        INSERT INTO alerts (
            id, event_type, source_ip, destination_ip,
            distinct_ports, time_window_seconds, severity,
            created_at, ai_status, ai_assessment, ai_error,
            status, acknowledged_at, resolved_at, analyst_notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            ai_status = excluded.ai_status,
            ai_assessment = excluded.ai_assessment,
            ai_error = excluded.ai_error
        "#,
    )
    .bind(&alert.id)
    .bind(&alert.event_type)
    .bind(&alert.source_ip)
    .bind(&alert.destination_ip)
    .bind(alert.distinct_ports)
    .bind(alert.time_window_seconds)
    .bind(&alert.severity)
    .bind(&alert.created_at)
    .bind(&alert.ai_status)
    .bind(assessment)
    .bind(&alert.ai_error)
    .bind(&alert.status)
    .bind(&alert.acknowledged_at)
    .bind(&alert.resolved_at)
    .bind(&alert.analyst_notes)
    .execute(pool)
    .await?;

    Ok(())
}

// Update only the AI analysis fields.
// Incident status, timestamps, and analyst notes remain untouched.
pub async fn update_ai_assessment(
    pool: &SqlitePool,
    alert_id: &str,
    ai_status: &str,
    assessment: Option<&crate::services::gemma::GemmaAssessment>,
    ai_error: Option<&str>,
) -> Result<(), sqlx::Error> {
    let assessment_json = assessment
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;

    sqlx::query(
        r#"
        UPDATE alerts
        SET ai_status = ?,
            ai_assessment = ?,
            ai_error = ?
        WHERE id = ?
        "#,
    )
    .bind(ai_status)
    .bind(assessment_json)
    .bind(ai_error)
    .bind(alert_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn update_incident(pool: &SqlitePool, alert: &Alert) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE alerts
        SET status = ?,
            acknowledged_at = ?,
            resolved_at = ?,
            analyst_notes = ?
        WHERE id = ?
        "#,
    )
    .bind(&alert.status)
    .bind(&alert.acknowledged_at)
    .bind(&alert.resolved_at)
    .bind(&alert.analyst_notes)
    .bind(&alert.id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_alert_by_id(
    pool: &SqlitePool,
    alert_id: &str,
) -> Result<Option<Alert>, sqlx::Error> {
    let row = sqlx::query("SELECT * FROM alerts WHERE id = ?")
        .bind(alert_id)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(row) => {
            let assessment_json: Option<String> = row.try_get("ai_assessment")?;

            let ai_assessment = assessment_json
                .map(|json| {
                    serde_json::from_str(&json)
                        .map_err(|error| sqlx::Error::Decode(Box::new(error)))
                })
                .transpose()?;

            Ok(Some(Alert {
                id: row.try_get("id")?,
                event_type: row.try_get("event_type")?,
                source_ip: row.try_get("source_ip")?,
                destination_ip: row.try_get("destination_ip")?,
                distinct_ports: row.try_get("distinct_ports")?,
                time_window_seconds: row.try_get("time_window_seconds")?,
                severity: row.try_get("severity")?,
                created_at: row.try_get("created_at")?,
                ai_status: row.try_get("ai_status")?,
                ai_assessment,
                ai_error: row.try_get("ai_error")?,
                status: row.try_get("status")?,
                acknowledged_at: row.try_get("acknowledged_at")?,
                resolved_at: row.try_get("resolved_at")?,
                analyst_notes: row.try_get("analyst_notes")?,
            }))
        }
        None => Ok(None),
    }
}

pub async fn list_alerts(pool: &SqlitePool) -> Result<Vec<Alert>, sqlx::Error> {
    let rows = sqlx::query("SELECT * FROM alerts ORDER BY created_at DESC")
        .fetch_all(pool)
        .await?;

    let mut alerts = Vec::new();

    for row in rows {
        let assessment_json: Option<String> = row.try_get("ai_assessment")?;

        let ai_assessment = assessment_json
            .map(|json| {
                serde_json::from_str(&json).map_err(|error| sqlx::Error::Decode(Box::new(error)))
            })
            .transpose()?;

        alerts.push(Alert {
            id: row.try_get("id")?,
            event_type: row.try_get("event_type")?,
            source_ip: row.try_get("source_ip")?,
            destination_ip: row.try_get("destination_ip")?,
            distinct_ports: row.try_get("distinct_ports")?,
            time_window_seconds: row.try_get("time_window_seconds")?,
            severity: row.try_get("severity")?,
            created_at: row.try_get("created_at")?,
            ai_status: row.try_get("ai_status")?,
            ai_assessment,
            ai_error: row.try_get("ai_error")?,
            status: row.try_get("status")?,
            acknowledged_at: row.try_get("acknowledged_at")?,
            resolved_at: row.try_get("resolved_at")?,
            analyst_notes: row.try_get("analyst_notes")?,
        });
    }

    Ok(alerts)
}

// Retrieve historical dashboard analytics.
pub async fn get_analytics(
    pool: &SqlitePool,
    period: &str,
) -> Result<AnalyticsResponse, sqlx::Error> {
    // These values are selected from a fixed allowlist in the API.
    let (modifier, bucket_format) = match period {
        "24h" => ("-24 hours", "%Y-%m-%d %H:00"),
        "7d" => ("-7 days", "%Y-%m-%d"),
        "30d" => ("-30 days", "%Y-%m-%d"),
        _ => ("-24 hours", "%Y-%m-%d %H:00"),
    };

    let summary = sqlx::query(
        r#"
        SELECT
            COUNT(*) AS total_alerts,
            SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) AS critical_alerts,
            SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) AS high_alerts,
            SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) AS medium_alerts,
            SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) AS low_alerts,
            SUM(CASE WHEN status != 'resolved' THEN 1 ELSE 0 END) AS open_incidents,
            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved_incidents,
            AVG(
                CASE
                    WHEN status = 'resolved' AND resolved_at IS NOT NULL
                    THEN (julianday(resolved_at) - julianday(created_at)) * 1440
                    ELSE NULL
                END
            ) AS average_resolution_minutes
        FROM alerts
        WHERE datetime(created_at) >= datetime('now', ?)
        "#,
    )
    .bind(modifier)
    .fetch_one(pool)
    .await?;

    let total_alerts: i64 = summary.try_get("total_alerts")?;
    let critical_alerts: i64 = summary.try_get("critical_alerts")?;
    let high_alerts: i64 = summary.try_get("high_alerts")?;
    let medium_alerts: i64 = summary.try_get("medium_alerts")?;
    let low_alerts: i64 = summary.try_get("low_alerts")?;
    let open_incidents: i64 = summary.try_get("open_incidents")?;
    let resolved_incidents: i64 = summary.try_get("resolved_incidents")?;
    let average_resolution_minutes: Option<f64> = summary.try_get("average_resolution_minutes")?;

    let time_rows = sqlx::query(
        r#"
        SELECT
            strftime(?, created_at) AS time_bucket,
            COUNT(*) AS alert_count
        FROM alerts
        WHERE datetime(created_at) >= datetime('now', ?)
        GROUP BY time_bucket
        ORDER BY time_bucket ASC
        "#,
    )
    .bind(bucket_format)
    .bind(modifier)
    .fetch_all(pool)
    .await?;

    let mut alerts_over_time = Vec::new();

    for row in time_rows {
        alerts_over_time.push(TimeBucket {
            timestamp: row.try_get("time_bucket")?,
            count: row.try_get("alert_count")?,
        });
    }

    let severity_rows = sqlx::query(
        r#"
        SELECT
            strftime(?, created_at) AS time_bucket,
            LOWER(severity) AS severity,
            COUNT(*) AS alert_count
        FROM alerts
        WHERE datetime(created_at) >= datetime('now', ?)
        GROUP BY time_bucket, LOWER(severity)
        ORDER BY time_bucket ASC
        "#,
    )
    .bind(bucket_format)
    .bind(modifier)
    .fetch_all(pool)
    .await?;

    let mut severity_over_time = Vec::new();

    for row in severity_rows {
        severity_over_time.push(SeverityBucket {
            timestamp: row.try_get("time_bucket")?,
            severity: row.try_get("severity")?,
            count: row.try_get("alert_count")?,
        });
    }

    let source_rows = sqlx::query(
        r#"
        SELECT source_ip, COUNT(*) AS alert_count
        FROM alerts
        WHERE datetime(created_at) >= datetime('now', ?)
        GROUP BY source_ip
        ORDER BY alert_count DESC
        LIMIT 10
        "#,
    )
    .bind(modifier)
    .fetch_all(pool)
    .await?;

    let mut top_sources = Vec::new();

    for row in source_rows {
        top_sources.push(SourceCount {
            source_ip: row.try_get("source_ip")?,
            count: row.try_get("alert_count")?,
        });
    }

    Ok(AnalyticsResponse {
        period: period.to_string(),
        total_alerts,
        critical_alerts,
        high_alerts,
        medium_alerts,
        low_alerts,
        open_incidents,
        resolved_incidents,
        average_resolution_minutes,
        alerts_over_time,
        severity_over_time,
        top_sources,
    })
}
