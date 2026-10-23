
import { useEffect, useState } from "react";
import "./App.css";

const API_URL = "http://localhost:8080/api/findings";

function App() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API_URL}/prioritized`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Unable to load security findings");
        }
        return response.json();
      })
      .then((data) => setFindings(data))
      .catch(() => setError("Could not connect to SecureDev backend."))
      .finally(() => setLoading(false));
  }, []);

  const countBySeverity = (severity) =>
    findings.filter((finding) => finding.severity === severity).length;

  const openCount = findings.filter(
    (finding) => finding.status === "OPEN"
  ).length;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">S</span>
          <span>SecureDev</span>
        </div>

        <p className="nav-label">WORKSPACE</p>
        <div className="nav-item active">◈ &nbsp; Security overview</div>
        <div className="nav-item">⌘ &nbsp; Scan findings</div>

        <div className="sidebar-bottom">
          <span className="status-dot" />
          Backend connection
          <strong>API</strong>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">DEVSECOPS PLATFORM</p>
            <h1>Security overview</h1>
            <p className="subtitle">
              Identify, prioritize, and manage security risks.
            </p>
          </div>
          <button className="refresh-button" onClick={() => window.location.reload()}>
            ↻ &nbsp; Refresh
          </button>
        </header>

        <section className="metrics">
          <Metric label="Total findings" value={findings.length} />
          <Metric label="Critical" value={countBySeverity("CRITICAL")} tone="critical" />
          <Metric label="High" value={countBySeverity("HIGH")} tone="high" />
          <Metric label="Open findings" value={openCount} tone="open" />
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Prioritized findings</h2>
              <p>Highest severity issues appear first.</p>
            </div>
            <span className="count-pill">{findings.length} findings</span>
          </div>

          {loading && <p className="message">Loading findings…</p>}
          {error && <p className="error">{error}</p>}

          {!loading && !error && (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>FINDING</th>
                    <th>SEVERITY</th>
                    <th>SOURCE</th>
                    <th>STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <strong>{finding.title}</strong>
                        <span className="description">
                          {finding.description}
                        </span>
                      </td>
                      <td>
                        <span className={`severity ${finding.severity.toLowerCase()}`}>
                          {finding.severity}
                        </span>
                      </td>
                      <td>{finding.sourceTool}</td>
                      <td>
                        <span className="status-pill">{finding.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {findings.length === 0 && (
                <p className="message">No findings available yet.</p>
              )}
            </div>
          )}
        </section>

        <footer>SecureDev · Security findings powered by your backend API</footer>
      </main>
    </div>
  );
}

function Metric({ label, value, tone = "" }) {
  return (
    <article className="metric-card">
      <p>{label}</p>
      <strong className={tone}>{value}</strong>
      <span>From connected findings</span>
    </article>
  );
}

export default App;
