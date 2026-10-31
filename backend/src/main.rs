mod database;
mod services;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, patch, post},
};
use chrono::{DateTime, Utc};
use database::{
    AnalyticsResponse, get_alert_by_id, get_analytics, initialize_database, list_alerts,
    save_alert, update_ai_assessment, update_incident,
};
use serde::{Deserialize, Serialize};
use services::gemma::{GemmaAssessment, GemmaClient};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

const SENSOR_TIMEOUT_SECONDS: i64 = 15;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    gemma: Arc<GemmaClient>,
    sensor: Arc<RwLock<Option<SensorRecord>>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub event_type: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub distinct_ports: u32,
    pub time_window_seconds: u32,
    pub severity: String,
    pub created_at: String,
    pub ai_status: String,
    pub ai_assessment: Option<GemmaAssessment>,
    pub ai_error: Option<String>,
    pub status: String,
    pub acknowledged_at: Option<String>,
    pub resolved_at: Option<String>,
    pub analyst_notes: Option<String>,
}

#[derive(Deserialize)]
struct NewAlert {
    event_type: String,
    source_ip: String,
    destination_ip: String,
    distinct_ports: u32,
    time_window_seconds: u32,
    severity: String,
}

#[derive(Deserialize)]
struct UpdateIncident {
    status: Option<String>,
    analyst_notes: Option<String>,
}

#[derive(Deserialize)]
struct AnalyticsQuery {
    period: Option<String>,
}

#[derive(Deserialize)]
struct SensorHeartbeat {
    interface: String,
    packets_captured: u64,
    alerts_generated: u64,
}

#[derive(Clone, Serialize)]
struct SensorRecord {
    interface: String,
    packets_captured: u64,
    alerts_generated: u64,
    last_seen: DateTime<Utc>,
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "online",
        "application": "SentinelAI",
        "database": "connected"
    }))
}

async fn get_alerts(State(state): State<AppState>) -> Result<Json<Vec<Alert>>, StatusCode> {
    match list_alerts(&state.db).await {
        Ok(alerts) => Ok(Json(alerts)),
        Err(error) => {
            eprintln!("[DATABASE] Failed to retrieve alerts: {}", error);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_dashboard_analytics(
    State(state): State<AppState>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<AnalyticsResponse>, StatusCode> {
    let period = query.period.as_deref().unwrap_or("24h");

    if !["24h", "7d", "30d"].contains(&period) {
        return Err(StatusCode::BAD_REQUEST);
    }

    match get_analytics(&state.db, period).await {
        Ok(analytics) => Ok(Json(analytics)),
        Err(error) => {
            eprintln!("[ANALYTICS] Failed to retrieve analytics: {}", error);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Save the alert immediately, then run Gemma analysis in the background.
async fn create_alert(
    State(state): State<AppState>,
    Json(payload): Json<NewAlert>,
) -> Result<(StatusCode, Json<Alert>), StatusCode> {
    let alert = Alert {
        id: Uuid::new_v4().to_string(),
        event_type: payload.event_type,
        source_ip: payload.source_ip,
        destination_ip: payload.destination_ip,
        distinct_ports: payload.distinct_ports,
        time_window_seconds: payload.time_window_seconds,
        severity: payload.severity,
        created_at: Utc::now().to_rfc3339(),
        ai_status: "processing".to_string(),
        ai_assessment: None,
        ai_error: None,
        status: "new".to_string(),
        acknowledged_at: None,
        resolved_at: None,
        analyst_notes: None,
    };

    println!(
        "[ALERT] Received {} from {}",
        alert.event_type, alert.source_ip
    );

    // Persist the alert before starting AI analysis.
    if let Err(error) = save_alert(&state.db, &alert).await {
        eprintln!("[DATABASE] Failed to save alert: {}", error);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let alert_data = serde_json::to_value(&alert).map_err(|error| {
        eprintln!("[ALERT] Could not serialize alert: {}", error);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let alert_id = alert.id.clone();
    let db = state.db.clone();
    let gemma = Arc::clone(&state.gemma);

    // Run Gemma without making the sensor wait for the AI response.
    tokio::spawn(async move {
        let result = gemma.analyze_alert(&alert_data).await;

        match result {
            Ok(assessment) => {
                println!("[GEMMA] Analysis completed for alert {}", alert_id);

                if let Err(error) =
                    update_ai_assessment(&db, &alert_id, "completed", Some(&assessment), None).await
                {
                    eprintln!(
                        "[DATABASE] Failed to save AI assessment for {}: {}",
                        alert_id, error
                    );
                }
            }

            Err(error) => {
                eprintln!("[GEMMA] Analysis failed for alert {}: {}", alert_id, error);

                if let Err(db_error) = update_ai_assessment(
                    &db,
                    &alert_id,
                    "failed",
                    None,
                    Some("AI analysis is currently unavailable"),
                )
                .await
                {
                    eprintln!(
                        "[DATABASE] Failed to save AI error for {}: {}",
                        alert_id, db_error
                    );
                }
            }
        }
    });

    // Return immediately. The frontend can retrieve the completed
    // assessment through its regular alerts polling.
    Ok((StatusCode::CREATED, Json(alert)))
}

// Update incident status and/or analyst notes.
async fn update_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
    Json(payload): Json<UpdateIncident>,
) -> Result<Json<Alert>, StatusCode> {
    const VALID_STATUSES: [&str; 4] = ["new", "acknowledged", "investigating", "resolved"];

    if payload.status.is_none() && payload.analyst_notes.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(ref status) = payload.status {
        if !VALID_STATUSES.contains(&status.as_str()) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let mut alert = match get_alert_by_id(&state.db, &alert_id).await {
        Ok(Some(alert)) => alert,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(error) => {
            eprintln!("[DATABASE] Failed to retrieve alert: {}", error);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if let Some(status) = payload.status {
        alert.status = status;

        if alert.status == "new" {
            alert.acknowledged_at = None;
            alert.resolved_at = None;
        } else {
            if alert.acknowledged_at.is_none() {
                alert.acknowledged_at = Some(Utc::now().to_rfc3339());
            }

            if alert.status == "resolved" {
                alert.resolved_at = Some(Utc::now().to_rfc3339());
            } else {
                alert.resolved_at = None;
            }
        }
    }

    if let Some(notes) = payload.analyst_notes {
        alert.analyst_notes = if notes.trim().is_empty() {
            None
        } else {
            Some(notes)
        };
    }

    if let Err(error) = update_incident(&state.db, &alert).await {
        eprintln!("[DATABASE] Failed to update incident: {}", error);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    println!(
        "[INCIDENT] Alert {} updated to status {}",
        alert.id, alert.status
    );

    Ok(Json(alert))
}

async fn update_sensor_heartbeat(
    State(state): State<AppState>,
    Json(payload): Json<SensorHeartbeat>,
) -> StatusCode {
    let record = SensorRecord {
        interface: payload.interface,
        packets_captured: payload.packets_captured,
        alerts_generated: payload.alerts_generated,
        last_seen: Utc::now(),
    };

    println!(
        "[SENSOR] Heartbeat | Interface: {} | Packets: {} | Alerts: {}",
        record.interface, record.packets_captured, record.alerts_generated
    );

    let mut sensor = state.sensor.write().await;
    *sensor = Some(record);

    StatusCode::OK
}

async fn get_sensor_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let sensor = state.sensor.read().await;

    match sensor.as_ref() {
        Some(record) => {
            let seconds_since_heartbeat = (Utc::now() - record.last_seen).num_seconds().max(0);

            let online = seconds_since_heartbeat <= SENSOR_TIMEOUT_SECONDS;

            Json(serde_json::json!({
                "status": if online { "online" } else { "offline" },
                "online": online,
                "interface": record.interface,
                "packets_captured": record.packets_captured,
                "alerts_generated": record.alerts_generated,
                "last_seen": record.last_seen.to_rfc3339(),
                "seconds_since_heartbeat": seconds_since_heartbeat
            }))
        }
        None => Json(serde_json::json!({
            "status": "offline",
            "online": false,
            "interface": null,
            "packets_captured": 0,
            "alerts_generated": 0,
            "last_seen": null,
            "seconds_since_heartbeat": null
        })),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = initialize_database().await?;

    let gemma = GemmaClient::from_env().map_err(std::io::Error::other)?;

    let state = AppState {
        db,
        gemma: Arc::new(gemma),
        sensor: Arc::new(RwLock::new(None)),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/alerts", get(get_alerts).post(create_alert))
        .route("/api/v1/alerts/{id}", patch(update_alert))
        .route("/api/v1/analytics", get(get_dashboard_analytics))
        .route("/api/v1/sensor/heartbeat", post(update_sensor_heartbeat))
        .route("/api/v1/sensor/status", get(get_sensor_status))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let address = format!("0.0.0.0:{}", port);

    let listener = tokio::net::TcpListener::bind(&address).await?;

    println!("SentinelAI running on {}", address);

    axum::serve(listener, app).await?;

    Ok(())
}
