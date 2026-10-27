
import { useEffect, useState } from "react";
import "./App.css";

const API_URL = "http://localhost:8080/api/findings";

function getRemediation(finding) {
  const text =
    `${finding.title} ${finding.description} ${finding.sourceTool}`.toLowerCase();

  if (/secret|api.?key|token|credential|password|gitleaks/.test(text)) {
    return {
      title: "Potential exposed secret",
      reason:
        "A credential or secret may be exposed. Investigate whether it is valid and accessible.",
      steps: [
        "Verify the finding without copying the secret into logs or chat.",
        "Revoke or rotate the credential if it is genuine.",
        "Remove the secret from source code and use environment variables or a secrets manager.",
        "Review repository history and access logs; removing a secret from the latest commit alone may not remove historical copies.",
        "Run the secret scanner again to verify remediation."
      ]
    };
  }

  if (/trivy|docker|container|image|cve|vulnerab|dependency|package/.test(text)) {
    return {
      title: "Potential vulnerable component",
      reason:
        "A software component or container may contain a known vulnerability. Confirm the affected package and version.",
      steps: [
        "Review the reported package, installed version, and vulnerability identifier.",
        "Check whether an upstream patched version is available.",
        "Update the affected package or base image to a supported patched version.",
        "Rebuild the image and run the vulnerability scan again.",
        "Test the application to check that the update has not introduced regressions."
      ]
    };
  }

  if (finding.severity === "CRITICAL" || finding.severity === "HIGH") {
    return {
      title: "Investigate high-priority finding",
      reason:
        "This finding has a high reported severity. Validate the issue and assess its impact before choosing a fix.",
      steps: [
        "Review the finding's title, description, source, and evidence.",
        "Confirm whether the issue affects your environment.",
        "Prioritize containment or remediation based on the verified impact.",
        "Apply the appropriate fix and test the affected component.",
        "Run the relevant security check again and document the result."
      ]
    };
  }

  return {
    title: "Investigate and remediate",
    reason:
      "The available finding details are not sufficient to recommend a specific technical fix. Investigate the evidence first.",
    steps: [
      "Review the finding description and source tool.",
      "Consult the relevant tool documentation for the reported issue.",
      "Reproduce or validate the issue in a safe test environment when possible.",
      "Apply a fix appropriate to the confirmed root cause.",
      "Repeat the relevant check and document the outcome."
    ]
  };
}

function App() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [page, setPage] = useState("overview");
  const [selectedFinding, setSelectedFinding] = useState(null);

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
  const [searchTerm, setSearchTerm] = useState("");
    const [severityFilter, setSeverityFilter] = useState("ALL");
    const [statusFilter, setStatusFilter] = useState("ALL");

    const filteredFindings = findings.filter((finding) => {
      const matchesSearch = `${finding.title} ${finding.description} ${finding.sourceTool}`
        .toLowerCase()
        .includes(searchTerm.toLowerCase());

      const matchesSeverity =
        severityFilter === "ALL" || finding.severity === severityFilter;

      const matchesStatus =
        statusFilter === "ALL" || finding.status === statusFilter;

      return matchesSearch && matchesSeverity && matchesStatus;
    });

  const updateFindingStatus = async (finding) => {
  const newStatus =
    finding.status === "OPEN" ? "RESOLVED" : "OPEN";

  try {
    const response = await fetch(
      `${API_URL}/${finding.id}/status`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ status: newStatus }),
      }
    );

    if (!response.ok) {
      throw new Error("Unable to update finding status");
    }

    const updatedFinding = await response.json();

    setFindings((current) =>
      current.map((item) =>
        item.id === updatedFinding.id ? updatedFinding : item
      )
    );

    setSelectedFinding((current) =>
      current?.id === updatedFinding.id ? updatedFinding : current
    );

    setError("");
  } catch {
    setError("Could not update finding status. Please try again.");
  }
};

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">S</span>
          <span>SecureDev</span>
        </div>

        <p className="nav-label">WORKSPACE</p>

        <button
          className={`nav-item ${page === "overview" ? "active" : ""}`}
          onClick={() => {
            setPage("overview");
            setSelectedFinding(null);
          }}
        >
          ◈ &nbsp; Security overview
        </button>

        <button
          className={`nav-item ${page === "findings" ? "active" : ""}`}
          onClick={() => {
            setPage("findings");
            setSelectedFinding(null);
          }}
        >
          ⌘ &nbsp; Scan findings
        </button>

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
            <h1>
              {selectedFinding
                ? "Remediation guidance"
                : page === "overview"
                  ? "Security overview"
                  : "Scan findings"}
            </h1>
            <p className="subtitle">
              {selectedFinding
                ? "Recommended investigation and remediation steps."
                : page === "overview"
                  ? "Identify, prioritize, and manage security risks."
                  : "Review security issues reported by connected tools."}
            </p>
          </div>

          <button
            className="refresh-button"
            onClick={() => window.location.reload()}
          >
            ↻ &nbsp; Refresh
          </button>
        </header>

        {!selectedFinding && page === "overview" && (
          <section className="metrics">
            <Metric label="Total findings" value={findings.length} />
            <Metric
              label="Critical"
              value={countBySeverity("CRITICAL")}
              tone="critical"
            />
            <Metric
              label="High"
              value={countBySeverity("HIGH")}
              tone="high"
            />
            <Metric
              label="Open findings"
              value={openCount}
              tone="open"
            />
          </section>
        )}

        {selectedFinding ? (
          <RemediationPanel
              finding={selectedFinding}
              onBack={() => setSelectedFinding(null)}
              onToggleStatus={updateFindingStatus}
            />
        ) : (
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>
                  {page === "overview"
                    ? "Prioritized findings"
                    : "Reported security findings"}
                </h2>
                <p>
                  {page === "overview"
                    ? "Highest severity issues appear first."
                    : "Existing findings from the backend; this page does not start a new scan."}
                </p>
              </div>
              <span className="count-pill">
                {findings.length} findings
              </span>
            </div>

            {loading && <p className="message">Loading findings…</p>}
            {error && <p className="error">{error}</p>}

            
{!loading && !error && (
  <>
    <div className="finding-filters">
      <input
        type="text"
        placeholder="Search by title, description, or source..."
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
      />

      <select
        value={severityFilter}
        onChange={(e) => setSeverityFilter(e.target.value)}
      >
        <option value="ALL">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>

      <select
        value={statusFilter}
        onChange={(e) => setStatusFilter(e.target.value)}
      >
        <option value="ALL">All Statuses</option>
        <option value="OPEN">Open</option>
        <option value="RESOLVED">Resolved</option>
      </select>
    </div>

    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>FINDING</th>
            <th>SEVERITY</th>
            <th>SOURCE</th>
            <th>STATUS</th>
            <th>ACTION</th>
          </tr>
        </thead>

        <tbody>
          {filteredFindings.map((finding) => (
            <tr key={finding.id}>
              <td>
                <strong>{finding.title}</strong>
                <span className="description">
                  {finding.description}
                </span>
              </td>

              <td>
                <span
                  className={`severity ${String(
                    finding.severity
                  ).toLowerCase()}`}
                >
                  {finding.severity}
                </span>
              </td>

              <td>{finding.sourceTool}</td>

              <td>
                <span className="status-pill">
                  {finding.status}
                </span>
              </td>

              <td>
                <button
                  className="status-action-button"
                  onClick={() => updateFindingStatus(finding)}
                >
                  {finding.status === "OPEN" ? "Resolve" : "Reopen"}
                </button>

                <button
                  className="remediation-button"
                  onClick={() => setSelectedFinding(finding)}
                >
                  View remediation
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {filteredFindings.length === 0 && (
        <p className="message">No matching findings.</p>
      )}
    </div>
  </>
)}

          </section>
        )}

        <footer>
          SecureDev · Rule-based remediation recommendations
        </footer>
      </main>
    </div>

  );
}

function RemediationPanel({ finding, onBack, onToggleStatus }) {
  const guidance = getRemediation(finding);

  return (
    <section className="panel remediation-panel">
      <div className="panel-heading">
        <div>
          <h2>{guidance.title}</h2>
          <p>{finding.title}</p>
        </div>
        <span
          className={`severity ${String(
            finding.severity
          ).toLowerCase()}`}
        >
          {finding.severity}
        </span>
      </div>

      <div className="remediation-content">
        <p className="remediation-reason">{guidance.reason}</p>

        <h3>Recommended steps</h3>
        <ol className="remediation-steps">
          {guidance.steps.map((step, index) => (
            <li key={step}>
              <span className="step-number">{index + 1}</span>
              <span>{step}</span>
            </li>
          ))}
        </ol>

        <div className="remediation-note">
          These are rule-based recommendations generated from the finding's
          available details. Validate the issue before applying a fix.
          SecureDev has not automatically remediated this finding.
        </div>
          <button
            className="status-action-button"
            onClick={() => onToggleStatus(finding)}
          >
            {finding.status === "OPEN"
              ? "Mark as resolved"
              : "Reopen finding"}
          </button>

          <button className="refresh-button" onClick={onBack}>
            ← &nbsp; Back to findings
          </button>
      </div>
    </section>
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
