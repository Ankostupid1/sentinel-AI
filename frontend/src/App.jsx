
import { useCallback, useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Bell,
  Check,
  CheckCircle,
  ChevronRight,
  Clock,
  Cpu,
  Database,
  Eye,
  FileText,
  Filter,
  LayoutDashboard,
  Loader2,
  Network,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import './App.css'

const api = axios.create({
  baseURL: '/',
  timeout: 10000,
})

const navigation = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'alerts', label: 'Live Alerts', icon: Bell },
  { id: 'analyst', label: 'AI Analyst', icon: Zap },
  { id: 'system', label: 'System Status', icon: Server },
]

const statusOptions = [
  { value: 'new', label: 'New' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'resolved', label: 'Resolved' },
]

const aiStatusOptions = [
  { value: 'All', label: 'All analyses' },
  { value: 'completed', label: 'Completed' },
  { value: 'processing', label: 'Processing' },
  { value: 'failed', label: 'Failed' },
]

const riskOptions = [
  { value: 'All', label: 'All risk levels' },
  { value: 'Critical', label: 'Critical' },
  { value: 'High', label: 'High' },
  { value: 'Medium', label: 'Medium' },
  { value: 'Low', label: 'Low' },
]

function formatDate(value) {
  if (!value) return 'Not recorded'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return value

  return date.toLocaleString()
}

function formatTimestamp(value, period) {
  if (!value) return ''

  if (period === '24h') {
    return value.slice(-5)
  }

  return value.slice(5)
}

function severityClass(value) {
  const severity = String(value || '').toLowerCase()

  if (severity === 'critical') return 'critical'
  if (severity === 'high') return 'high'
  if (severity === 'medium') return 'medium'
  if (severity === 'low') return 'low'

  if (severity === 'acknowledged') return 'acknowledged'
  if (severity === 'investigating') return 'investigating'
  if (severity === 'resolved') return 'resolved'

  return 'new'
}

function getStatusLabel(status) {
  return (
    statusOptions.find((option) => option.value === status)?.label || 'New'
  )
}

function getAIStatusLabel(status) {
  const labels = {
    completed: 'Completed',
    processing: 'Processing',
    failed: 'Failed',
  }

  return labels[status] || 'Not started'
}

function getAIStatusClass(status) {
  if (status === 'completed') return 'completed'
  if (status === 'failed') return 'failed'
  return 'pending'
}

function getConfidence(value) {
  if (value == null || Number.isNaN(Number(value))) return null

  const confidence = Number(value)

  return confidence <= 1
    ? Math.round(confidence * 100)
    : Math.min(Math.round(confidence), 100)
}

function StatCard({ title, value, description, icon: Icon }) {
  return (
    <div className="stat-card">
      <div className="stat-card-top">
        <span className="stat-title">{title}</span>
        <span className="stat-icon">
          <Icon size={19} />
        </span>
      </div>

      <div className="stat-value">{value}</div>

      <div className="stat-description">
        <span>{description}</span>
      </div>
    </div>
  )
}

function StatusIndicator({ online, label }) {
  return (
    <div className="status-indicator">
      <span className={`status-dot ${online ? 'online' : 'offline'}`} />
      <span>{label}</span>
      <span className="status-text">
        {online ? 'Operational' : 'Unavailable'}
      </span>
    </div>
  )
}

function SeverityBadge({ severity }) {
  return (
    <span className={`severity-badge ${severityClass(severity)}`}>
      {severity || 'Unknown'}
    </span>
  )
}

function AIStatusBadge({ status }) {
  const normalized = status || 'processing'

  return (
    <span className={`ai-status ${getAIStatusClass(normalized)}`}>
      {normalized === 'processing' && (
        <Loader2 size={12} className="spin" />
      )}
      {getAIStatusLabel(normalized)}
    </span>
  )
}

function IncidentStatusBadge({ status }) {
  const normalizedStatus = status || 'new'

  return (
    <span className={`incident-status ${severityClass(normalizedStatus)}`}>
      {getStatusLabel(normalizedStatus)}
    </span>
  )
}

function AlertTable({ alerts, onSelect }) {
  if (alerts.length === 0) {
    return (
      <div className="empty-state">
        <ShieldCheck size={34} />
        <h3>No alerts found</h3>
        <p>There are no alerts matching your current filters.</p>
      </div>
    )
  }

  return (
    <div className="table-wrapper">
      <table className="alerts-table">
        <thead>
          <tr>
            <th>EVENT</th>
            <th>SOURCE IP</th>
            <th>DESTINATION IP</th>
            <th>RISK LEVEL</th>
            <th>AI STATUS</th>
            <th>INCIDENT STATUS</th>
            <th>TIME</th>
            <th />
          </tr>
        </thead>

        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} onClick={() => onSelect(alert)}>
              <td>
                <div className="event-cell">
                  <span className="event-icon">
                    <AlertTriangle size={15} />
                  </span>
                  <span>
                    {String(alert.event_type || 'Unknown event').replaceAll(
                      '_',
                      ' ',
                    )}
                  </span>
                </div>
              </td>

              <td className="ip-address">{alert.source_ip || '—'}</td>
              <td className="ip-address">
                {alert.destination_ip || '—'}
              </td>

              <td>
                <SeverityBadge severity={alert.severity} />
              </td>

              <td>
                <AIStatusBadge status={alert.ai_status} />
              </td>

              <td>
                <IncidentStatusBadge status={alert.status} />
              </td>

              <td className="time-cell">{formatDate(alert.created_at)}</td>

              <td>
                <ChevronRight size={16} className="table-chevron" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null

  return (
    <div className="chart-tooltip">
      <span>{label}</span>
      <strong>{payload[0].value} alerts</strong>
    </div>
  )
}

function AssessmentList({ title, items }) {
  if (!Array.isArray(items) || items.length === 0) return null

  return (
    <div className="assessment-block">
      <span>{title}</span>
      <ul>
        {items.map((item, index) => (
          <li key={`${title}-${index}`}>{item}</li>
        ))}
      </ul>
    </div>
  )
}

function AlertDetailsModal({
  alert,
  onClose,
  onUpdate,
  notesDraft,
  setNotesDraft,
  updatingIncident,
  incidentError,
}) {
  if (!alert) return null

  const currentStatus = alert.status || 'new'
  const assessment = alert.ai_assessment
  const confidence = getConfidence(assessment?.confidence)

  const changeStatus = (status) => {
    onUpdate({ status })
  }

  const saveNotes = () => {
    onUpdate({ analyst_notes: notesDraft })
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="alert-modal"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-header">
          <div>
            <span className="section-eyebrow">SECURITY INCIDENT</span>
            <h2>Alert details</h2>
            <p className="modal-subtitle">{alert.id}</p>
          </div>

          <button className="icon-button" onClick={onClose}>
            <X size={20} />
          </button>
        </div>

        <div className="modal-content">
          <div className="incident-facts">
            <div className="fact-card">
              <span>Event type</span>
              <strong>
                {String(alert.event_type || 'Unknown').replaceAll('_', ' ')}
              </strong>
            </div>

            <div className="fact-card">
              <span>Severity</span>
              <SeverityBadge severity={alert.severity} />
            </div>

            <div className="fact-card">
              <span>Source IP</span>
              <strong>{alert.source_ip || '—'}</strong>
            </div>

            <div className="fact-card">
              <span>Destination IP</span>
              <strong>{alert.destination_ip || '—'}</strong>
            </div>

            <div className="fact-card">
              <span>Distinct ports</span>
              <strong>{alert.distinct_ports ?? '—'}</strong>
            </div>

            <div className="fact-card">
              <span>Time window</span>
              <strong>
                {alert.time_window_seconds != null
                  ? `${alert.time_window_seconds} seconds`
                  : '—'}
              </strong>
            </div>
          </div>

          <section className="incident-management">
            <div className="section-heading">
              <div>
                <span className="section-eyebrow">RESPONSE WORKFLOW</span>
                <h3>Incident management</h3>
              </div>

              <IncidentStatusBadge status={currentStatus} />
            </div>

            <label className="field-label" htmlFor="incident-status">
              Incident status
            </label>

            <select
              id="incident-status"
              className="incident-select"
              value={currentStatus}
              disabled={updatingIncident}
              onChange={(event) => changeStatus(event.target.value)}
            >
              {statusOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>

            <div className="incident-actions">
              {currentStatus === 'new' && (
                <button
                  className="incident-action-button"
                  disabled={updatingIncident}
                  onClick={() => changeStatus('acknowledged')}
                >
                  <Check size={15} />
                  Acknowledge
                </button>
              )}

              {currentStatus !== 'investigating' &&
                currentStatus !== 'resolved' && (
                  <button
                    className="incident-action-button"
                    disabled={updatingIncident}
                    onClick={() => changeStatus('investigating')}
                  >
                    <Eye size={15} />
                    Investigate
                  </button>
                )}

              {currentStatus !== 'resolved' && (
                <button
                  className="incident-action-button resolve"
                  disabled={updatingIncident}
                  onClick={() => changeStatus('resolved')}
                >
                  <CheckCircle size={15} />
                  Resolve
                </button>
              )}

              {currentStatus === 'resolved' && (
                <button
                  className="incident-action-button"
                  disabled={updatingIncident}
                  onClick={() => changeStatus('new')}
                >
                  <RefreshCw size={15} />
                  Reopen
                </button>
              )}
            </div>

            <label className="field-label" htmlFor="analyst-notes">
              Analyst notes
            </label>

            <textarea
              id="analyst-notes"
              className="analyst-notes-input"
              value={notesDraft}
              onChange={(event) => setNotesDraft(event.target.value)}
              placeholder="Record investigation findings, actions taken, or observations..."
              rows={4}
              disabled={updatingIncident}
            />

            <button
              className="save-notes-button"
              onClick={saveNotes}
              disabled={updatingIncident}
            >
              {updatingIncident ? (
                <>
                  <Loader2 size={15} className="spin" />
                  Saving...
                </>
              ) : (
                <>
                  <FileText size={15} />
                  Save analyst notes
                </>
              )}
            </button>

            {incidentError && (
              <div className="incident-error">
                <AlertCircle size={15} />
                {incidentError}
              </div>
            )}

            <div className="incident-timestamps">
              <div>
                <span>Acknowledged</span>
                <strong>{formatDate(alert.acknowledged_at)}</strong>
              </div>

              <div>
                <span>Resolved</span>
                <strong>{formatDate(alert.resolved_at)}</strong>
              </div>
            </div>
          </section>

          <section className="ai-assessment">
            <div className="section-heading">
              <div>
                <span className="section-eyebrow">GEMMA 4 ANALYSIS</span>
                <h3>AI security assessment</h3>
              </div>

              <AIStatusBadge status={alert.ai_status} />
            </div>

            {assessment ? (
              <div className="assessment-content">
                {assessment.classification && (
                  <div className="assessment-block">
                    <span>Threat classification</span>
                    <strong>{assessment.classification}</strong>
                  </div>
                )}

                {assessment.risk_level && (
                  <div className="assessment-block">
                    <span>Risk level</span>
                    <SeverityBadge severity={assessment.risk_level} />
                  </div>
                )}

                {confidence != null && (
                  <div className="assessment-block">
                    <span>Model confidence</span>
                    <strong>{confidence}%</strong>
                    <div className="confidence-track">
                      <div
                        className="confidence-fill"
                        style={{ width: `${confidence}%` }}
                      />
                    </div>
                    <small>
                      Model-reported confidence, not a verified probability.
                    </small>
                  </div>
                )}

                {assessment.summary && (
                  <div className="assessment-block">
                    <span>Analysis summary</span>
                    <p>{assessment.summary}</p>
                  </div>
                )}

                <AssessmentList
                  title="Observed evidence"
                  items={assessment.evidence}
                />

                <AssessmentList
                  title="Recommended analyst actions"
                  items={assessment.recommendations}
                />

                <AssessmentList
                  title="Analysis limitations"
                  items={assessment.limitations}
                />
              </div>
            ) : (
              <div className="empty-state compact">
                {alert.ai_status === 'processing' ? (
                  <>
                    <Loader2 size={25} className="spin" />
                    <p>Gemma is analysing this security event.</p>
                    <small>
                      The assessment will appear here when processing finishes.
                    </small>
                  </>
                ) : alert.ai_status === 'failed' ? (
                  <>
                    <AlertCircle size={24} />
                    <p>AI analysis could not be completed.</p>
                    <small>
                      {alert.ai_error ||
                        'The AI service is currently unavailable.'}
                    </small>
                  </>
                ) : (
                  <>
                    <AlertCircle size={22} />
                    <p>No AI assessment is available for this alert.</p>
                  </>
                )}
              </div>
            )}
          </section>
        </div>

        <div className="modal-footer">
          <span>Created {formatDate(alert.created_at)}</span>
          <button className="secondary-button" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  )
}

function App() {
  const [activePage, setActivePage] = useState('overview')
  const [alerts, setAlerts] = useState([])
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [health, setHealth] = useState(null)
  const [sensor, setSensor] = useState(null)

  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [apiError, setApiError] = useState('')

  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('All')
  const [statusFilter, setStatusFilter] = useState('All')

  const [notesDraft, setNotesDraft] = useState('')
  const [updatingIncident, setUpdatingIncident] = useState(false)
  const [incidentError, setIncidentError] = useState('')

  const [analytics, setAnalytics] = useState(null)
  const [analyticsPeriod, setAnalyticsPeriod] = useState('24h')
  const [analyticsLoading, setAnalyticsLoading] = useState(false)
  const [analyticsError, setAnalyticsError] = useState('')

  // AI Analyst workspace filters.
  const [aiSearch, setAiSearch] = useState('')
  const [aiStatusFilter, setAiStatusFilter] = useState('All')
  const [aiRiskFilter, setAiRiskFilter] = useState('All')

  const fetchAnalytics = useCallback(async () => {
    setAnalyticsLoading(true)

    try {
      const response = await api.get(
        `/api/v1/analytics?period=${analyticsPeriod}`,
      )

      setAnalytics(response.data)
      setAnalyticsError('')
    } catch (error) {
      setAnalyticsError(
        error.response?.data?.message ||
          'Unable to load dashboard analytics.',
      )
    } finally {
      setAnalyticsLoading(false)
    }
  }, [analyticsPeriod])

  const fetchData = useCallback(async (showRefresh = false) => {
    if (showRefresh) setRefreshing(true)

    try {
      const [alertsResponse, healthResponse] = await Promise.all([
        api.get('/api/v1/alerts'),
        api.get('/health'),
      ])

      const latestAlerts = alertsResponse.data

      setAlerts(latestAlerts)

      setSelectedAlert((current) =>
        current
          ? latestAlerts.find((alert) => alert.id === current.id) || current
          : null,
      )

      setHealth(healthResponse.data)
      setApiError('')
    } catch (error) {
      setApiError(
        error.response?.data?.message ||
          'Unable to connect to the SentinelAI backend.',
      )
    }

    try {
      const sensorResponse = await api.get('/api/v1/sensor/status')
      setSensor(sensorResponse.data)
    } catch {
      setSensor(null)
    }

    setLoading(false)
    setRefreshing(false)
  }, [])

  useEffect(() => {
    fetchData()

    const interval = setInterval(() => {
      fetchData()
    }, 5000)

    return () => clearInterval(interval)
  }, [fetchData])

  useEffect(() => {
    fetchAnalytics()
  }, [fetchAnalytics])

  const handleRefresh = () => {
    fetchData(true)
    fetchAnalytics()
  }

  const updateIncident = async (changes) => {
    if (!selectedAlert || updatingIncident) return

    setUpdatingIncident(true)
    setIncidentError('')

    try {
      const response = await api.patch(
        `/api/v1/alerts/${selectedAlert.id}`,
        changes,
      )

      const updatedAlert = response.data

      setAlerts((currentAlerts) =>
        currentAlerts.map((alert) =>
          alert.id === updatedAlert.id ? updatedAlert : alert,
        ),
      )

      setSelectedAlert(updatedAlert)
      setNotesDraft(updatedAlert.analyst_notes || '')

      fetchAnalytics()
    } catch (error) {
      setIncidentError(
        error.response?.data?.message ||
          'Unable to update this incident. Please try again.',
      )
    } finally {
      setUpdatingIncident(false)
    }
  }

  const openAlert = (alert) => {
    setSelectedAlert(alert)
    setNotesDraft(alert.analyst_notes || '')
    setIncidentError('')
  }

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const searchText = [
        alert.event_type,
        alert.source_ip,
        alert.destination_ip,
        alert.id,
      ]
        .join(' ')
        .toLowerCase()

      const matchesSearch = searchText.includes(search.toLowerCase())

      const matchesSeverity =
        severityFilter === 'All' ||
        String(alert.severity || '').toLowerCase() ===
          severityFilter.toLowerCase()

      const matchesStatus =
        statusFilter === 'All' ||
        (alert.status || 'new') === statusFilter

      return matchesSearch && matchesSeverity && matchesStatus
    })
  }, [alerts, search, severityFilter, statusFilter])

  const totalAlerts = analytics?.total_alerts ?? 0
  const criticalAlerts = analytics?.critical_alerts ?? 0
  const highAlerts = analytics?.high_alerts ?? 0
  const mediumAlerts = analytics?.medium_alerts ?? 0
  const lowAlerts = analytics?.low_alerts ?? 0

  const unresolvedAlerts = analytics?.open_incidents ?? 0
  const resolvedAlerts = analytics?.resolved_incidents ?? 0
  const averageResolution = analytics?.average_resolution_minutes

  const aiAnalyzed = alerts.filter(
    (alert) => alert.ai_status === 'completed',
  ).length

  const aiProcessing = alerts.filter(
    (alert) => alert.ai_status === 'processing',
  ).length

  const aiFailed = alerts.filter(
    (alert) => alert.ai_status === 'failed',
  ).length

  const aiAssessments = useMemo(() => {
    return alerts.filter((alert) => {
      const assessment = alert.ai_assessment
      const searchText = [
        alert.event_type,
        alert.source_ip,
        alert.destination_ip,
        alert.id,
        assessment?.classification,
        assessment?.summary,
      ]
        .join(' ')
        .toLowerCase()

      const matchesSearch = searchText.includes(aiSearch.toLowerCase())

      const matchesStatus =
        aiStatusFilter === 'All' ||
        alert.ai_status === aiStatusFilter

      const riskLevel = assessment?.risk_level || alert.severity

      const matchesRisk =
        aiRiskFilter === 'All' ||
        String(riskLevel || '').toLowerCase() ===
          aiRiskFilter.toLowerCase()

      return matchesSearch && matchesStatus && matchesRisk
    })
  }, [alerts, aiSearch, aiStatusFilter, aiRiskFilter])

  const riskData = useMemo(() => {
    if (!analytics) return []

    return [
      { name: 'Critical', value: criticalAlerts },
      { name: 'High', value: highAlerts },
      { name: 'Medium', value: mediumAlerts },
      { name: 'Low', value: lowAlerts },
    ].filter((item) => item.value > 0)
  }, [analytics, criticalAlerts, highAlerts, mediumAlerts, lowAlerts])

  const currentActivity = useMemo(() => {
    return (analytics?.alerts_over_time || []).map((item) => ({
      time: formatTimestamp(item.timestamp, analyticsPeriod),
      alerts: item.count,
    }))
  }, [analytics, analyticsPeriod])

  const severityTrend = useMemo(() => {
    const grouped = {}

    for (const item of analytics?.severity_over_time || []) {
      if (!grouped[item.timestamp]) {
        grouped[item.timestamp] = {
          time: formatTimestamp(item.timestamp, analyticsPeriod),
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
        }
      }

      const severity = String(item.severity).toLowerCase()

      if (Object.hasOwn(grouped[item.timestamp], severity)) {
        grouped[item.timestamp][severity] = item.count
      }
    }

    return Object.values(grouped)
  }, [analytics, analyticsPeriod])

  const topSources = analytics?.top_sources || []

  const apiOnline = Boolean(health)
  const sensorOnline = Boolean(sensor?.online)

  // The current health endpoint does not expose Gemma's live availability.
  // Do not report the model as operational based only on backend availability.
  const gemmaOnline = alerts.some((alert) => alert.ai_status === 'completed')

  const renderOverview = () => (
    <>
      <div className="page-heading">
        <div>
          <span className="section-eyebrow">SECURITY OPERATIONS CENTER</span>
          <h1>Overview</h1>
          <p>Monitor your network security posture in real time.</p>
        </div>

        <div className="overview-actions">
          <select
            className="analytics-period-select"
            value={analyticsPeriod}
            onChange={(event) => setAnalyticsPeriod(event.target.value)}
          >
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>

          <button
            className="refresh-button"
            onClick={handleRefresh}
            disabled={refreshing || analyticsLoading}
          >
            <RefreshCw
              size={15}
              className={refreshing || analyticsLoading ? 'spin' : ''}
            />
            Refresh
          </button>
        </div>
      </div>

      {analyticsError && (
        <div className="api-error-banner">
          <AlertCircle size={17} />
          <span>{analyticsError}</span>
          <button onClick={fetchAnalytics}>Retry</button>
        </div>
      )}

      <div className="stats-grid">
        <StatCard
          title="Total Alerts"
          value={analyticsLoading && !analytics ? '—' : totalAlerts}
          description={`Recorded in the last ${analyticsPeriod}`}
          icon={Bell}
        />

        <StatCard
          title="Critical Alerts"
          value={analyticsLoading && !analytics ? '—' : criticalAlerts}
          description={`${highAlerts} high severity alerts`}
          icon={AlertTriangle}
        />

        <StatCard
          title="Open Incidents"
          value={analyticsLoading && !analytics ? '—' : unresolvedAlerts}
          description={`${resolvedAlerts} resolved incidents`}
          icon={ShieldAlert}
        />

        <StatCard
          title="Avg. Resolution"
          value={
            averageResolution != null
              ? `${averageResolution.toFixed(1)} min`
              : '—'
          }
          description="Average time to resolve incidents"
          icon={Clock}
        />
      </div>

      <div className="dashboard-grid">
        <section className="panel activity-panel">
          <div className="panel-header">
            <div>
              <h3>Threat activity</h3>
              <p>Alert activity over the selected period</p>
            </div>

            <span className="panel-icon">
              <Activity size={18} />
            </span>
          </div>

          {currentActivity.length > 0 ? (
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={currentActivity}>
                  <defs>
                    <linearGradient
                      id="alertGradient"
                      x1="0"
                      y1="0"
                      x2="0"
                      y2="1"
                    >
                      <stop offset="0%" stopColor="#6366f1" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#6366f1" stopOpacity={0} />
                    </linearGradient>
                  </defs>

                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(148, 163, 184, 0.1)"
                  />

                  <XAxis
                    dataKey="time"
                    stroke="#64748b"
                    tickLine={false}
                    axisLine={false}
                  />

                  <YAxis
                    allowDecimals={false}
                    stroke="#64748b"
                    tickLine={false}
                    axisLine={false}
                  />

                  <Tooltip content={<ChartTooltip />} />

                  <Area
                    type="monotone"
                    dataKey="alerts"
                    stroke="#818cf8"
                    strokeWidth={2}
                    fill="url(#alertGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="empty-state compact">
              <Activity size={28} />
              <p>No alert activity recorded for this period.</p>
            </div>
          )}
        </section>

        <section className="panel risk-panel">
          <div className="panel-header">
            <div>
              <h3>Risk distribution</h3>
              <p>Alerts grouped by severity</p>
            </div>

            <span className="panel-icon">
              <Shield size={18} />
            </span>
          </div>

          {riskData.length > 0 ? (
            <>
              <div className="risk-chart">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={riskData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={55}
                      outerRadius={82}
                      paddingAngle={4}
                    >
                      {riskData.map((entry) => {
                        const colors = {
                          Critical: '#ef4444',
                          High: '#f97316',
                          Medium: '#eab308',
                          Low: '#22c55e',
                        }

                        return (
                          <Cell key={entry.name} fill={colors[entry.name]} />
                        )
                      })}
                    </Pie>

                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="risk-legend">
                {riskData.map((item) => (
                  <div className="risk-legend-item" key={item.name}>
                    <span className={`risk-dot ${severityClass(item.name)}`} />
                    <span>{item.name}</span>
                    <strong>{item.value}</strong>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="empty-state compact">
              <ShieldCheck size={28} />
              <p>No risk data available for this period.</p>
            </div>
          )}
        </section>
      </div>

      <div className="dashboard-grid">
        <section className="panel activity-panel">
          <div className="panel-header">
            <div>
              <h3>Severity trend</h3>
              <p>Alert severity over the selected reporting period</p>
            </div>

            <span className="panel-icon">
              <ShieldAlert size={18} />
            </span>
          </div>

          {severityTrend.length > 0 ? (
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={severityTrend}>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(148, 163, 184, 0.1)"
                  />

                  <XAxis
                    dataKey="time"
                    stroke="#64748b"
                    tickLine={false}
                    axisLine={false}
                  />

                  <YAxis
                    allowDecimals={false}
                    stroke="#64748b"
                    tickLine={false}
                    axisLine={false}
                  />

                  <Tooltip />

                  <Area
                    type="monotone"
                    dataKey="critical"
                    name="Critical"
                    stackId="1"
                    stroke="#ef4444"
                    fill="#ef4444"
                    fillOpacity={0.35}
                  />

                  <Area
                    type="monotone"
                    dataKey="high"
                    name="High"
                    stackId="1"
                    stroke="#f97316"
                    fill="#f97316"
                    fillOpacity={0.35}
                  />

                  <Area
                    type="monotone"
                    dataKey="medium"
                    name="Medium"
                    stackId="1"
                    stroke="#eab308"
                    fill="#eab308"
                    fillOpacity={0.35}
                  />

                  <Area
                    type="monotone"
                    dataKey="low"
                    name="Low"
                    stackId="1"
                    stroke="#22c55e"
                    fill="#22c55e"
                    fillOpacity={0.35}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="empty-state compact">
              <ShieldCheck size={28} />
              <p>No severity trend data available for this period.</p>
            </div>
          )}
        </section>

        <section className="panel risk-panel">
          <div className="panel-header">
            <div>
              <h3>Top source IPs</h3>
              <p>Sources generating the most alerts</p>
            </div>

            <span className="panel-icon">
              <Network size={18} />
            </span>
          </div>

          {topSources.length > 0 ? (
            <div className="top-sources-list">
              {topSources.map((source, index) => (
                <div className="top-source-item" key={source.source_ip}>
                  <div className="top-source-rank">{index + 1}</div>

                  <div className="top-source-info">
                    <strong>{source.source_ip}</strong>
                    <span>
                      {source.count} {source.count === 1 ? 'alert' : 'alerts'}
                    </span>
                  </div>

                  <div className="top-source-count">{source.count}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state compact">
              <Network size={28} />
              <p>No source IP data available for this period.</p>
            </div>
          )}
        </section>
      </div>

      <section className="panel telemetry-panel">
        <div className="panel-header">
          <div>
            <h3>System telemetry</h3>
            <p>Current health of SentinelAI components</p>
          </div>

          <span className="panel-icon">
            <Cpu size={18} />
          </span>
        </div>

        <div className="telemetry-grid">
          <StatusIndicator online={apiOnline} label="Backend API" />
          <StatusIndicator online={apiOnline} label="SQLite Database" />
          <StatusIndicator online={gemmaOnline} label="Gemma AI" />
          <StatusIndicator online={sensorOnline} label="Network Sensor" />
        </div>
      </section>

      <section className="panel recent-alerts-panel">
        <div className="panel-header">
          <div>
            <h3>Recent alerts</h3>
            <p>Latest detected security events</p>
          </div>

          <button className="text-button" onClick={() => setActivePage('alerts')}>
            View all <ChevronRight size={15} />
          </button>
        </div>

        <AlertTable alerts={alerts.slice(0, 5)} onSelect={openAlert} />
      </section>
    </>
  )

  const renderAlerts = () => (
    <>
      <div className="page-heading">
        <div>
          <span className="section-eyebrow">THREAT MONITORING</span>
          <h1>Live Alerts</h1>
          <p>Review, filter, and manage detected security incidents.</p>
        </div>

        <button
          className="refresh-button"
          onClick={handleRefresh}
          disabled={refreshing || analyticsLoading}
        >
          <RefreshCw size={15} className={refreshing ? 'spin' : ''} />
          Refresh
        </button>
      </div>

      <section className="panel alerts-panel">
        <div className="alert-controls">
          <div className="search-box">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search events or IP addresses..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>

          <div className="table-controls">
            <div className="filter-control">
              <Filter size={15} />
              <select
                value={severityFilter}
                onChange={(event) => setSeverityFilter(event.target.value)}
              >
                <option value="All">All severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>

            <div className="filter-control">
              <Activity size={15} />
              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
              >
                <option value="All">All incident statuses</option>
                <option value="new">New</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>
          </div>
        </div>

        <div className="table-summary">
          <span>
            Showing <strong>{filteredAlerts.length}</strong> of{' '}
            <strong>{alerts.length}</strong> alerts
          </span>

          <span className="live-indicator">
            <span className="status-dot online" />
            Live updates enabled
          </span>
        </div>

        <AlertTable alerts={filteredAlerts} onSelect={openAlert} />
      </section>
    </>
  )

  // AI Analyst workspace
  const renderAnalyst = () => (
    <>
      <div className="page-heading">
        <div>
          <span className="section-eyebrow">ARTIFICIAL INTELLIGENCE</span>
          <h1>AI Analyst</h1>
          <p>
            Review Gemma-generated threat assessments, supporting evidence,
            and recommended investigation actions.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={handleRefresh}
          disabled={refreshing}
        >
          <RefreshCw size={15} className={refreshing ? 'spin' : ''} />
          Refresh
        </button>
      </div>

      <div className="stats-grid">
        <StatCard
          title="Completed Analyses"
          value={aiAnalyzed}
          description="Alerts assessed by Gemma"
          icon={CheckCircle}
        />

        <StatCard
          title="Processing"
          value={aiProcessing}
          description="Awaiting AI assessment"
          icon={Clock}
        />

        <StatCard
          title="Failed Analyses"
          value={aiFailed}
          description="Require attention"
          icon={AlertCircle}
        />

        <StatCard
          title="Total Alerts"
          value={alerts.length}
          description="Available for AI analysis"
          icon={Zap}
        />
      </div>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>AI analysis history</h3>
            <p>
              Search and filter alerts by analysis status, risk level, or
              incident details.
            </p>
          </div>

          <span className="panel-icon">
            <Zap size={18} />
          </span>
        </div>

        <div className="alert-controls">
          <div className="search-box">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search classifications, IP addresses, or summaries..."
              value={aiSearch}
              onChange={(event) => setAiSearch(event.target.value)}
            />
          </div>

          <div className="table-controls">
            <div className="filter-control">
              <Activity size={15} />
              <select
                value={aiStatusFilter}
                onChange={(event) => setAiStatusFilter(event.target.value)}
              >
                {aiStatusOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-control">
              <Filter size={15} />
              <select
                value={aiRiskFilter}
                onChange={(event) => setAiRiskFilter(event.target.value)}
              >
                {riskOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <div className="table-summary">
          <span>
            Showing <strong>{aiAssessments.length}</strong> of{' '}
            <strong>{alerts.length}</strong> alerts
          </span>

          <span className="live-indicator">
            <span className="status-dot online" />
            AI status updates enabled
          </span>
        </div>

        {aiAssessments.length > 0 ? (
          <div className="analyst-list">
            {aiAssessments.map((alert) => {
              const assessment = alert.ai_assessment
              const confidence = getConfidence(assessment?.confidence)

              return (
                <button
                  className="analyst-item"
                  key={alert.id}
                  onClick={() => openAlert(alert)}
                >
                  <div className="analyst-item-icon">
                    {alert.ai_status === 'processing' ? (
                      <Loader2 size={18} className="spin" />
                    ) : alert.ai_status === 'failed' ? (
                      <AlertCircle size={18} />
                    ) : (
                      <Zap size={18} />
                    )}
                  </div>

                  <div className="analyst-item-content">
                    <strong>
                      {assessment?.classification ||
                        String(alert.event_type || 'Unknown event').replaceAll(
                          '_',
                          ' ',
                        )}
                    </strong>

                    <span>
                      {alert.source_ip} → {alert.destination_ip}
                    </span>

                    <small>
                      {assessment?.summary ||
                        (alert.ai_status === 'processing'
                          ? 'Gemma is analysing this alert.'
                          : alert.ai_status === 'failed'
                            ? alert.ai_error || 'Analysis failed.'
                            : 'No assessment summary available.')}
                    </small>

                    <small>{formatDate(alert.created_at)}</small>

                    {confidence != null && (
                      <small>Model confidence: {confidence}%</small>
                    )}
                  </div>

                  <div className="analyst-item-meta">
                    <AIStatusBadge status={alert.ai_status} />
                    <SeverityBadge
                      severity={assessment?.risk_level || alert.severity}
                    />
                    <IncidentStatusBadge status={alert.status} />
                  </div>

                  <ChevronRight size={17} />
                </button>
              )
            })}
          </div>
        ) : (
          <div className="empty-state">
            <Zap size={34} />
            <h3>No matching AI assessments</h3>
            <p>
              Try changing your filters, or wait for new alerts to be analysed.
            </p>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>How to interpret AI assessments</h3>
            <p>Keep model-generated findings in their proper context.</p>
          </div>

          <span className="panel-icon">
            <ShieldCheck size={18} />
          </span>
        </div>

        <div className="assessment-guidance">
          <div>
            <strong>Evidence</strong>
            <p>
              Network observations supplied to the model. These should be
              distinguishable from conclusions inferred by the model.
            </p>
          </div>

          <div>
            <strong>Recommendations</strong>
            <p>
              Suggested actions for an analyst to review. They are not
              automatically executed by SentinelAI.
            </p>
          </div>

          <div>
            <strong>Limitations</strong>
            <p>
              Missing context or uncertainty that may affect the assessment.
              Validate important findings using network and endpoint evidence.
            </p>
          </div>
        </div>
      </section>
    </>
  )

  const renderSystem = () => (
    <>
      <div className="page-heading">
        <div>
          <span className="section-eyebrow">INFRASTRUCTURE</span>
          <h1>System Status</h1>
          <p>Monitor the availability of SentinelAI services.</p>
        </div>

        <button
          className="refresh-button"
          onClick={handleRefresh}
          disabled={refreshing || analyticsLoading}
        >
          <RefreshCw size={15} className={refreshing ? 'spin' : ''} />
          Refresh
        </button>
      </div>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>Service health</h3>
            <p>Component availability based on backend responses.</p>
          </div>
        </div>

        <div className="system-service-list">
          <div className="system-service">
            <div className="system-service-icon">
              <Server size={20} />
            </div>

            <div className="system-service-info">
              <strong>Backend API</strong>
              <span>Rust / Axum application server</span>
            </div>

            <StatusIndicator online={apiOnline} label="" />
          </div>

          <div className="system-service">
            <div className="system-service-icon">
              <Database size={20} />
            </div>

            <div className="system-service-info">
              <strong>SQLite Database</strong>
              <span>Security alert and incident storage</span>
            </div>

            <StatusIndicator online={apiOnline} label="" />
          </div>

          <div className="system-service">
            <div className="system-service-icon">
              <Zap size={20} />
            </div>

            <div className="system-service-info">
              <strong>Gemma AI</strong>
              <span>AI-powered security assessment</span>
            </div>

            <StatusIndicator online={gemmaOnline} label="" />
          </div>

          <div className="system-service">
            <div className="system-service-icon">
              <Network size={20} />
            </div>

            <div className="system-service-info">
              <strong>Network Sensor</strong>
              <span>Local network traffic monitoring</span>
            </div>

            <StatusIndicator online={sensorOnline} label="" />
          </div>
        </div>
      </section>

      <section className="panel system-details">
        <div className="panel-header">
          <div>
            <h3>Sensor information</h3>
            <p>Last reported sensor heartbeat.</p>
          </div>
        </div>

        <div className="system-detail-grid">
          <div>
            <span>Sensor status</span>
            <strong>{sensorOnline ? 'Online' : 'Offline'}</strong>
          </div>

          <div>
            <span>Network interface</span>
            <strong>{sensor?.interface || 'Not available'}</strong>
          </div>

          <div>
            <span>Last heartbeat</span>
            <strong>{formatDate(sensor?.last_seen)}</strong>
          </div>

          <div>
            <span>Packets captured</span>
            <strong>{sensor?.packets_captured ?? 0}</strong>
          </div>

          <div>
            <span>Alerts generated</span>
            <strong>{sensor?.alerts_generated ?? 0}</strong>
          </div>
        </div>
      </section>
    </>
  )

  const pageContent = {
    overview: renderOverview,
    alerts: renderAlerts,
    analyst: renderAnalyst,
    system: renderSystem,
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo">
            <Shield size={23} />
          </div>

          <div className="brand-name">
            <strong>
              Sentinel<span>AI</span>
            </strong>
            <small>SECURITY PLATFORM</small>
          </div>
        </div>

        <div className="sidebar-section-label">WORKSPACE</div>

        <nav className="sidebar-nav">
          {navigation.map((item) => {
            const Icon = item.icon

            return (
              <button
                key={item.id}
                className={`nav-item ${
                  activePage === item.id ? 'active' : ''
                }`}
                onClick={() => setActivePage(item.id)}
              >
                <Icon size={18} />
                <span>{item.label}</span>

                {item.id === 'alerts' && unresolvedAlerts > 0 && (
                  <span className="nav-count">{unresolvedAlerts}</span>
                )}
              </button>
            )
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-system-status">
            <span
              className={`status-dot ${apiOnline ? 'online' : 'offline'}`}
            />

            <div>
              <strong>System status</strong>
              <small>
                {apiOnline ? 'All services monitored' : 'Connection issue'}
              </small>
            </div>
          </div>

          <div className="sidebar-version">
            SENTINELAI · LOCAL DEPLOYMENT
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            <span>SentinelAI</span>
            <ChevronRight size={14} />

            <strong>
              {navigation.find((item) => item.id === activePage)?.label}
            </strong>
          </div>

          <div className="topbar-right">
            <span className="topbar-status">
              <span
                className={`status-dot ${apiOnline ? 'online' : 'offline'}`}
              />
              {apiOnline ? 'System online' : 'System offline'}
            </span>

            <div className="topbar-avatar">SA</div>
          </div>
        </header>

        <div className="content-area">
          {apiError && (
            <div className="api-error-banner">
              <AlertCircle size={17} />
              <span>{apiError}</span>

              <button onClick={handleRefresh}>Retry</button>
            </div>
          )}

          {loading ? (
            <div className="loading-state">
              <Loader2 size={28} className="spin" />
              <p>Loading SentinelAI...</p>
            </div>
          ) : (
            pageContent[activePage]()
          )}
        </div>
      </main>

      {selectedAlert && (
        <AlertDetailsModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onUpdate={updateIncident}
          notesDraft={notesDraft}
          setNotesDraft={setNotesDraft}
          updatingIncident={updatingIncident}
          incidentError={incidentError}
        />
      )}
    </div>
  )
}

export default App
