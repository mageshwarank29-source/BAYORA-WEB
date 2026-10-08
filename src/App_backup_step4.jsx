import { useEffect, useMemo, useState } from "react";
import "./App.css";

const API_BASE = "/api";

const attackTypes = [
  "Prompt Injection",
  "Jailbreak",
  "Sensitive Information",
  "Malicious Instruction",
];

function App() {
  const [activePage, setActivePage] = useState("Dashboard");
  const [attackType, setAttackType] = useState("Prompt Injection");
  const [prompt, setPrompt] = useState("");
  const [result, setResult] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [backendOnline, setBackendOnline] = useState(false);

  const loadLogs = async () => {
    try {
      const response = await fetch(`${API_BASE}/audit-logs`);

      if (!response.ok) {
        throw new Error("Failed to load logs");
      }

      const data = await response.json();

      setLogs(data.logs || []);
      setBackendOnline(true);
    } catch (error) {
      console.error(error);
      setBackendOnline(false);
    }
  };

  useEffect(() => {
    loadLogs();

    const interval = setInterval(loadLogs, 5000);

    return () => clearInterval(interval);
  }, []);

  const stats = useMemo(() => {
    const blocked = logs.filter(
      (log) => log.decision === "BLOCK"
    ).length;

    const review = logs.filter(
      (log) => log.decision === "REVIEW"
    ).length;

    const critical = logs.filter(
      (log) => log.risk_level === "HIGH"
    ).length;

    return {
      tests: logs.length,
      blocked,
      review,
      critical,
    };
  }, [logs]);

  const runSecurityTest = async () => {
    if (!prompt.trim()) {
      alert("Please enter an adversarial prompt.");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(
        `${API_BASE}/security-test`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            attack_type: attackType,
            prompt: prompt,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok || data.success === false) {
        throw new Error(
          data.error || "Security test failed."
        );
      }

      setResult(data);

      setPrompt("");

      await loadLogs();
    } catch (error) {
      console.error(error);

      alert(
        "Unable to connect to Bayora Security API. Make sure the backend is running on port 8000."
      );
    } finally {
      setLoading(false);
    }
  };

  const getDecisionClass = (decision) => {
    if (decision === "BLOCK") return "danger";
    if (decision === "REVIEW") return "warning";
    return "success";
  };

  const getRiskClass = (level) => {
    if (level === "HIGH") return "danger";
    if (level === "MEDIUM") return "warning";
    return "success";
  };

  return (
    <div className="app-shell">

      {/* SIDEBAR */}

      <aside className="sidebar">

        <div className="brand">
          <div className="brand-mark">B</div>

          <div>
            <h1>BAYORA</h1>
            <span>AI SECURITY PLATFORM</span>
          </div>
        </div>

        <div className="sidebar-section">
          <p className="sidebar-label">
            PLATFORM
          </p>

          <button
            className={
              activePage === "Dashboard"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActivePage("Dashboard")}
          >
            <span>▦</span>
            Dashboard
          </button>

          <button
            className={
              activePage === "Security Lab"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActivePage("Security Lab")}
          >
            <span>⌁</span>
            Security Lab
          </button>

          <button
            className={
              activePage === "Security Zones"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActivePage("Security Zones")}
          >
            <span>◈</span>
            Security Zones
          </button>
        </div>

        <div className="sidebar-section">
          <p className="sidebar-label">
            GOVERNANCE
          </p>

          <button
            className={
              activePage === "Policies"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActivePage("Policies")}
          >
            <span>⊙</span>
            Policies
          </button>

          <button
            className={
              activePage === "Audit Logs"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActivePage("Audit Logs")}
          >
            <span>≡</span>
            Audit Logs
          </button>
        </div>

        <div className="sidebar-bottom">

          <div className="system-status">
            <div className="status-dot"></div>

            <div>
              <strong>System Operational</strong>
              <span>
                {backendOnline
                  ? "Security engine connected"
                  : "Backend offline"}
              </span>
            </div>
          </div>

          <div className="version">
            BAYORA v2.0
          </div>

        </div>

      </aside>


      {/* MAIN */}

      <main className="main-content">

        {/* TOP BAR */}

        <header className="topbar">

          <div>
            <p className="breadcrumb">
              BAYORA / {activePage.toUpperCase()}
            </p>

            <h2>{activePage}</h2>
          </div>

          <div className="topbar-right">

            <div className="live-status">
              <span className="pulse"></span>
              LIVE MONITORING
            </div>

            <div className="user-badge">
              SEC
            </div>

          </div>

        </header>


        {/* DASHBOARD */}

        {activePage === "Dashboard" && (

          <section className="page-content">

            <div className="hero-card">

              <div>
                <span className="eyebrow">
                  ADVERSARIAL AI SECURITY
                </span>

                <h1>
                  Security Command Center
                </h1>

                <p>
                  Monitor adversarial activity,
                  policy decisions and AI security
                  events from one control plane.
                </p>
              </div>

              <div className="hero-shield">
                ◈
              </div>

            </div>


            <div className="stats-grid">

              <StatCard
                label="ACTIVE TESTS"
                value={stats.tests}
                icon="◎"
              />

              <StatCard
                label="BLOCKED ATTACKS"
                value={stats.blocked}
                icon="✕"
              />

              <StatCard
                label="REVIEW QUEUE"
                value={stats.review}
                icon="!"
              />

              <StatCard
                label="HIGH RISK EVENTS"
                value={stats.critical}
                icon="◆"
              />

            </div>


            <div className="dashboard-grid">

              <div className="panel">

                <div className="panel-header">

                  <div>
                    <span className="eyebrow">
                      LIVE ACTIVITY
                    </span>

                    <h3>
                      Recent Security Events
                    </h3>
                  </div>

                  <button
                    className="ghost-button"
                    onClick={() =>
                      setActivePage("Audit Logs")
                    }
                  >
                    VIEW ALL
                  </button>

                </div>

                <EventList logs={logs.slice(0, 6)} />

              </div>


              <div className="panel">

                <div className="panel-header">

                  <div>
                    <span className="eyebrow">
                      POLICY ENGINE
                    </span>

                    <h3>
                      Gateway Status
                    </h3>
                  </div>

                  <span className="online-badge">
                    ACTIVE
                  </span>

                </div>

                <div className="gateway-status">

                  <GatewayRow
                    name="Threat Detection"
                    status="ACTIVE"
                  />

                  <GatewayRow
                    name="Risk Scoring"
                    status="ACTIVE"
                  />

                  <GatewayRow
                    name="Policy Evaluation"
                    status="ACTIVE"
                  />

                  <GatewayRow
                    name="Interception Layer"
                    status="ACTIVE"
                  />

                  <GatewayRow
                    name="Audit Logging"
                    status="ACTIVE"
                  />

                </div>

              </div>

            </div>

          </section>
        )}


        {/* SECURITY LAB */}

        {activePage === "Security Lab" && (

          <section className="page-content">

            <div className="section-heading">

              <div>

                <span className="eyebrow">
                  ADVERSARIAL TESTING
                </span>

                <h1>
                  Security Lab
                </h1>

                <p>
                  Submit a suspicious prompt and let
                  Bayora evaluate its security risk.
                </p>

              </div>

              <div className="live-badge">
                <span className="pulse"></span>
                LIVE
              </div>

            </div>


            <div className="lab-grid">

              {/* TEST FORM */}

              <div className="panel test-panel">

                <div className="panel-header">

                  <div>
                    <span className="eyebrow">
                      RED ZONE
                    </span>

                    <h3>
                      Run an adversarial test
                    </h3>
                  </div>

                  <span className="zone-badge red">
                    ATTACKER
                  </span>

                </div>


                <label>
                  ATTACK TYPE
                </label>

                <select
                  value={attackType}
                  onChange={(e) =>
                    setAttackType(e.target.value)
                  }
                >
                  {attackTypes.map((type) => (
                    <option
                      key={type}
                      value={type}
                    >
                      {type}
                    </option>
                  ))}
                </select>


                <label>
                  ADVERSARIAL PROMPT
                </label>

                <textarea
                  value={prompt}
                  onChange={(e) =>
                    setPrompt(e.target.value)
                  }
                  placeholder="Enter a suspicious prompt to test the Bayora security engine..."
                  rows="8"
                />


                <button
                  className="run-button"
                  onClick={runSecurityTest}
                  disabled={loading}
                >
                  {loading
                    ? "ANALYZING..."
                    : "RUN SECURITY TEST →"}
                </button>

              </div>


              {/* RESULT */}

              <div className="panel result-panel">

                {!result && (

                  <div className="empty-result">

                    <div className="empty-icon">
                      ◈
                    </div>

                    <h3>
                      Awaiting Security Test
                    </h3>

                    <p>
                      Run an adversarial test to
                      view the Policy Gateway analysis.
                    </p>

                  </div>

                )}


                {result && (

                  <div className="security-result">

                    <div className="result-title">

                      <div>
                        <span className="eyebrow">
                          ANALYSIS RESULT
                        </span>

                        <h3>
                          Threat Assessment
                        </h3>
                      </div>

                      <div
                        className={`decision-badge ${getDecisionClass(
                          result.decision
                        )}`}
                      >
                        {result.decision}
                      </div>

                    </div>


                    <div
                      className={`threat-banner ${getDecisionClass(
                        result.decision
                      )}`}
                    >

                      <div className="threat-icon">
                        {result.decision === "BLOCK"
                          ? "✕"
                          : result.decision === "REVIEW"
                          ? "!"
                          : "✓"}
                      </div>

                      <div>

                        <strong>
                          {result.decision === "BLOCK"
                            ? "THREAT BLOCKED"
                            : result.decision === "REVIEW"
                            ? "THREAT REQUIRES REVIEW"
                            : "REQUEST ALLOWED"}
                        </strong>

                        <span>
                          {result.message}
                        </span>

                      </div>

                    </div>


                    {/* RISK */}

                    <div className="risk-section">

                      <div className="risk-header">

                        <span>
                          SECURITY RISK
                        </span>

                        <strong>
                          {result.risk_score}
                          <small>/100</small>
                        </strong>

                      </div>

                      <div className="risk-bar">

                        <div
                          className={`risk-fill ${getRiskClass(
                            result.risk_level
                          )}`}
                          style={{
                            width: `${result.risk_score}%`,
                          }}
                        />

                      </div>

                    </div>


                    {/* DETAILS */}

                    <div className="detail-grid">

                      <Detail
                        label="ATTACK TYPE"
                        value={result.attack_type}
                      />

                      <Detail
                        label="RISK LEVEL"
                        value={result.risk_level}
                        className={getRiskClass(
                          result.risk_level
                        )}
                      />

                      <Detail
                        label="DECISION"
                        value={result.decision}
                        className={getDecisionClass(
                          result.decision
                        )}
                      />

                      <Detail
                        label="INCIDENT ID"
                        value={result.incident_id}
                      />

                    </div>


                    {/* POLICY GATEWAY */}

                    <div className="policy-card">

                      <div className="policy-card-header">

                        <div>

                          <span className="eyebrow">
                            POLICY GATEWAY
                          </span>

                          <h4>
                            Security Policy Decision
                          </h4>

                        </div>

                        <span className="gateway-icon">
                          🛡
                        </span>

                      </div>


                      <div className="policy-grid">

                        <div>
                          <span>
                            POLICY ID
                          </span>

                          <strong>
                            {result.policy_id}
                          </strong>
                        </div>

                        <div>
                          <span>
                            POLICY
                          </span>

                          <strong>
                            {result.policy_name}
                          </strong>
                        </div>

                        <div>
                          <span>
                            ACTION TAKEN
                          </span>

                          <strong
                            className={
                              result.intercepted
                                ? "text-warning"
                                : "text-success"
                            }
                          >
                            {result.action_taken}
                          </strong>
                        </div>

                        <div>
                          <span>
                            INTERCEPTION
                          </span>

                          <strong
                            className={
                              result.intercepted
                                ? "text-warning"
                                : "text-success"
                            }
                          >
                            {result.intercepted
                              ? "REQUEST INTERCEPTED"
                              : "NOT INTERCEPTED"}
                          </strong>
                        </div>

                      </div>


                      <div className="policy-reason">

                        <span>
                          POLICY REASON
                        </span>

                        <p>
                          {result.policy_reason}
                        </p>

                      </div>

                    </div>


                    {/* THREATS */}

                    <div className="threat-list">

                      <span className="eyebrow">
                        DETECTED THREATS
                      </span>

                      {result.detected_threats &&
                      result.detected_threats.length > 0 ? (

                        <div className="threat-tags">

                          {result.detected_threats.map(
                            (threat) => (
                              <span
                                className="threat-tag"
                                key={threat}
                              >
                                {threat}
                              </span>
                            )
                          )}

                        </div>

                      ) : (

                        <span className="no-threat">
                          No significant threat detected
                        </span>

                      )}

                    </div>


                    {/* INDICATORS */}

                    {result.matched_indicators &&
                      result.matched_indicators.length >
                        0 && (

                        <div className="indicator-section">

                          <span className="eyebrow">
                            MATCHED INDICATORS
                          </span>

                          <div className="indicator-list">

                            {result.matched_indicators.map(
                              (indicator) => (
                                <span
                                  key={indicator}
                                >
                                  {indicator}
                                </span>
                              )
                            )}

                          </div>

                        </div>
                      )}

                  </div>
                )}

              </div>

            </div>

          </section>
        )}


        {/* SECURITY ZONES */}

        {activePage === "Security Zones" && (

          <section className="page-content">

            <div className="section-heading">

              <div>

                <span className="eyebrow">
                  ZERO TRUST ARCHITECTURE
                </span>

                <h1>
                  Security Zones
                </h1>

                <p>
                  Visualize how adversarial requests
                  move through Bayora's security boundary.
                </p>

              </div>

            </div>


            <div className="zones-flow">

              <Zone
                type="red"
                title="RED ZONE"
                subtitle="ATTACKER"
                description="Untrusted adversarial input enters the testing environment."
              />

              <div className="flow-arrow">
                →
              </div>

              <Zone
                type="gateway"
                title="POLICY GATEWAY"
                subtitle="ZERO TRUST"
                description="Threat detection, risk scoring and policy enforcement."
              />

              <div className="flow-arrow">
                →
              </div>

              <Zone
                type="blue"
                title="MODEL ZONE"
                subtitle="CONTROLLED"
                description="Only approved requests are allowed toward model execution."
              />

              <div className="flow-arrow">
                →
              </div>

              <Zone
                type="cyan"
                title="BLUE ZONE"
                subtitle="MONITORED"
                description="Outputs and security events remain under continuous monitoring."
              />

            </div>


            <div className="panel architecture-panel">

              <div className="panel-header">

                <div>
                  <span className="eyebrow">
                    SECURITY PIPELINE
                  </span>

                  <h3>
                    Request Enforcement Flow
                  </h3>
                </div>

              </div>

              <div className="pipeline">

                <PipelineStep
                  number="01"
                  title="ADVERSARIAL INPUT"
                  text="Untrusted prompt submitted for testing."
                />

                <PipelineStep
                  number="02"
                  title="THREAT DETECTION"
                  text="Security signatures identify suspicious behavior."
                />

                <PipelineStep
                  number="03"
                  title="RISK SCORING"
                  text="Bayora calculates a security risk score."
                />

                <PipelineStep
                  number="04"
                  title="POLICY DECISION"
                  text="Request is allowed, reviewed or blocked."
                />

                <PipelineStep
                  number="05"
                  title="AUDIT EVENT"
                  text="Security event is permanently recorded."
                />

              </div>

            </div>

          </section>
        )}


        {/* POLICIES */}

        {activePage === "Policies" && (

          <section className="page-content">

            <div className="section-heading">

              <div>

                <span className="eyebrow">
                  GOVERNANCE
                </span>

                <h1>
                  Security Policies
                </h1>

                <p>
                  Active enforcement policies used by
                  the Bayora Policy Gateway.
                </p>

              </div>

            </div>


            <div className="policy-list">

              <PolicyRow
                id="AI-SAFETY-001"
                name="High Risk AI Attack Prevention"
                threshold="70 – 100"
                action="BLOCK"
              />

              <PolicyRow
                id="AI-SAFETY-002"
                name="Medium Risk Security Review"
                threshold="40 – 69"
                action="REVIEW"
              />

              <PolicyRow
                id="AI-SAFETY-003"
                name="Low Risk Request Allowance"
                threshold="0 – 39"
                action="ALLOW"
              />

            </div>

          </section>
        )}


        {/* AUDIT LOGS */}

        {activePage === "Audit Logs" && (

          <section className="page-content">

            <div className="section-heading">

              <div>

                <span className="eyebrow">
                  FORENSICS
                </span>

                <h1>
                  Audit Logs
                </h1>

                <p>
                  Persistent security events recorded by
                  the Bayora Security Engine.
                </p>

              </div>

              <button
                className="ghost-button"
                onClick={loadLogs}
              >
                ↻ REFRESH
              </button>

            </div>


            <div className="panel audit-panel">

              {logs.length === 0 ? (

                <div className="empty-result">

                  <div className="empty-icon">
                    ≡
                  </div>

                  <h3>
                    No audit events
                  </h3>

                  <p>
                    Run a security test to create
                    your first incident.
                  </p>

                </div>

              ) : (

                <div className="audit-table-wrapper">

                  <table>

                    <thead>

                      <tr>

                        <th>
                          INCIDENT
                        </th>

                        <th>
                          ATTACK
                        </th>

                        <th>
                          RISK
                        </th>

                        <th>
                          DECISION
                        </th>

                        <th>
                          POLICY
                        </th>

                        <th>
                          ACTION
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      {logs.map((log) => (

                        <tr key={log.incident_id}>

                          <td>
                            <strong>
                              {log.incident_id}
                            </strong>
                          </td>

                          <td>
                            {log.attack_type}
                          </td>

                          <td>

                            <span
                              className={`table-risk ${getRiskClass(
                                log.risk_level
                              )}`}
                            >
                              {log.risk_score}
                            </span>

                          </td>

                          <td>

                            <span
                              className={`table-decision ${getDecisionClass(
                                log.decision
                              )}`}
                            >
                              {log.decision}
                            </span>

                          </td>

                          <td>
                            {log.policy_id ||
                              "AI-SAFETY-001"}
                          </td>

                          <td>
                            {log.action_taken ||
                              "—"}
                          </td>

                        </tr>

                      ))}

                    </tbody>

                  </table>

                </div>

              )}

            </div>

          </section>
        )}

      </main>

    </div>
  );
}


/* ============================================================
   COMPONENTS
   ============================================================ */

function StatCard({ label, value, icon }) {

  return (

    <div className="stat-card">

      <div className="stat-icon">
        {icon}
      </div>

      <div>

        <span>
          {label}
        </span>

        <strong>
          {value}
        </strong>

      </div>

    </div>
  );
}


function Detail({
  label,
  value,
  className = "",
}) {

  return (

    <div className="detail-item">

      <span>
        {label}
      </span>

      <strong className={className}>
        {value}
      </strong>

    </div>
  );
}


function GatewayRow({ name, status }) {

  return (

    <div className="gateway-row">

      <span className="gateway-check">
        ✓
      </span>

      <span>
        {name}
      </span>

      <strong>
        {status}
      </strong>

    </div>
  );
}


function EventList({ logs }) {

  if (!logs.length) {

    return (

      <div className="empty-events">
        No security events recorded yet.
      </div>
    );
  }

  return (

    <div className="event-list">

      {logs.map((log) => (

        <div
          className="event-row"
          key={log.incident_id}
        >

          <div
            className={`event-status ${log.decision.toLowerCase()}`}
          >
            {log.decision === "BLOCK"
              ? "✕"
              : log.decision === "REVIEW"
              ? "!"
              : "✓"}
          </div>

          <div className="event-main">

            <strong>
              {log.attack_type}
            </strong>

            <span>
              {log.incident_id}
            </span>

          </div>

          <div className="event-risk">

            <strong>
              {log.risk_score}
            </strong>

            <span>
              {log.risk_level}
            </span>

          </div>

        </div>
      ))}

    </div>
  );
}


function Zone({
  type,
  title,
  subtitle,
  description,
}) {

  return (

    <div className={`zone-card ${type}`}>

      <div className="zone-icon">
        {type === "gateway" ? "🛡" : "◈"}
      </div>

      <span>
        {subtitle}
      </span>

      <h3>
        {title}
      </h3>

      <p>
        {description}
      </p>

    </div>
  );
}


function PipelineStep({
  number,
  title,
  text,
}) {

  return (

    <div className="pipeline-step">

      <div className="pipeline-number">
        {number}
      </div>

      <div>

        <strong>
          {title}
        </strong>

        <p>
          {text}
        </p>

      </div>

    </div>
  );
}


function PolicyRow({
  id,
  name,
  threshold,
  action,
}) {

  const className =
    action === "BLOCK"
      ? "danger"
      : action === "REVIEW"
      ? "warning"
      : "success";

  return (

    <div className="policy-row">

      <div className="policy-id">
        {id}
      </div>

      <div className="policy-name">

        <strong>
          {name}
        </strong>

        <span>
          Risk threshold: {threshold}
        </span>

      </div>

      <div className={`policy-action ${className}`}>
        {action}
      </div>

    </div>
  );
}


export default App;