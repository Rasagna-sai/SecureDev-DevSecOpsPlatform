
import { useState } from "react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  LineChart,
  Line,
} from "recharts";

const SEVERITY_COLORS = {
  CRITICAL: "#ff747e",
  HIGH: "#ffb66b",
  MEDIUM: "#e9d477",
  LOW: "#72d6ef",
};

function SecurityAnalytics({ findings }) {
    const [dateRange, setDateRange] = useState("ALL");
  const severityData = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(
    (severity) => ({
      name: severity,
      value: findings.filter(
        (finding) => finding.severity === severity
      ).length,
    })
  );

  const statusData = ["OPEN", "RESOLVED"].map((status) => ({
    name: status,
    value: findings.filter(
      (finding) => finding.status === status
    ).length,
  }));

  const scannerData = Object.entries(
    findings.reduce((counts, finding) => {
      const scanner = finding.sourceTool || "Unknown";
      counts[scanner] = (counts[scanner] || 0) + 1;
      return counts;
    }, {})
  ).map(([name, value]) => ({ name, value }));

  const filteredTrendFindings = findings.filter((finding) => {
  if (!finding.detectedAt) return false;
  if (dateRange === "ALL") return true;

  const findingDate = new Date(finding.detectedAt);
  const today = new Date();

  const startDate = new Date();
  startDate.setDate(today.getDate() - Number(dateRange));
  startDate.setHours(0, 0, 0, 0);

  today.setHours(23, 59, 59, 999);

  return findingDate >= startDate && findingDate <= today;
});

  const trendData = Object.entries(
  filteredTrendFindings.reduce((counts, finding) => {
    if (!finding.detectedAt) return counts;

    const dateKey = finding.detectedAt.slice(0, 10);
    counts[dateKey] = (counts[dateKey] || 0) + 1;

    return counts;
  }, {})
)
  .sort(([dateA], [dateB]) => dateA.localeCompare(dateB))
  .map(([dateKey, count]) => {
    const [year, month, day] = dateKey.split("-").map(Number);

    return {
      date: new Date(year, month - 1, day).toLocaleDateString("en-IN", {
        day: "2-digit",
        month: "short",
      }),
      count,
    };
  });

  const total = findings.length;
  const resolved = statusData.find(
    (item) => item.name === "RESOLVED"
  ).value;

  const resolutionRate =
    total === 0 ? 0 : Math.round((resolved / total) * 100);

  return (
    <section className="analytics-section">
      <div className="analytics-heading">
        <div>
          <h2>Security Analytics</h2>
          <p>Visual insights from your reported security findings.</p>
        </div>

        <span className="analytics-total">
          {total} total findings
        </span>
      </div>

      <div className="analytics-summary">
        <article className="analytics-card">
          <span>Resolution rate</span>
          <strong>{resolutionRate}%</strong>
          <p>{resolved} of {total} findings resolved</p>
        </article>

        <article className="analytics-card">
          <span>Open findings</span>
          <strong>
            {statusData.find((item) => item.name === "OPEN").value}
          </strong>
          <p>Require investigation or remediation</p>
        </article>
      </div>

      <div className="analytics-grid">
        <article className="analytics-panel">
          <h3>Severity distribution</h3>
          <p>Findings grouped by reported severity.</p>

          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={severityData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={65}
                outerRadius={95}
                paddingAngle={3}
              >
                {severityData.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={SEVERITY_COLORS[entry.name]}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#111620",
                  border: "1px solid #34483f",
                  borderRadius: "8px",
                  color: "#e7eaf2",
                }}
              />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </article>

        <article className="analytics-panel">
          <h3>Finding status</h3>
          <p>Open versus resolved security findings.</p>

          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={statusData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={65}
                outerRadius={95}
                paddingAngle={3}
              >
                {statusData.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={
                      entry.name === "OPEN"
                        ? "#ffb66b"
                        : "#72f0b1"
                    }
                  />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </article>

        <article className="analytics-panel scanner-panel">
          <h3>Findings by scanner</h3>
          <p>Reported findings grouped by source tool.</p>
          <div className="trend-filter">
            <label htmlFor="trendRange">Date range:</label>
            <select
                id="trendRange"
                value={dateRange}
                onChange={(e) => setDateRange(e.target.value)}
            >
                <option value="7">Last 7 days</option>
                <option value="30">Last 30 days</option>
                <option value="ALL">All time</option>
            </select>
            </div>

          {scannerData.length === 0 ? (
            <p className="analytics-empty">
              No scanner findings available.
            </p>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart
                data={scannerData}
                margin={{ top: 15, right: 15, left: 0, bottom: 5 }}
              >
                <CartesianGrid
                  stroke="#252c39"
                  strokeDasharray="3 3"
                />
                <XAxis
                  dataKey="name"
                  stroke="#9099ad"
                  tick={{ fontSize: 11 }}
                />
                <YAxis
                  allowDecimals={false}
                  stroke="#9099ad"
                  tick={{ fontSize: 11 }}
                />
                <Tooltip />
                <Bar
                  dataKey="value"
                  name="Findings"
                  fill="#72f0b1"
                  radius={[5, 5, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          )}
        </article>
        <article className="analytics-panel scanner-panel">
            <h3>Finding trends over time</h3>
            <p>Number of security findings detected on each date.</p>

            {trendData.length === 0 ? (
                <p className="analytics-empty">
                No detection date information available.
                </p>
            ) : (
                <ResponsiveContainer width="100%" height={280}>
                <LineChart data={trendData}>
                    <CartesianGrid stroke="#252c39" strokeDasharray="3 3" />
                    <XAxis dataKey="date" stroke="#9099ad" />
                    <YAxis allowDecimals={false} stroke="#9099ad" />
                    <Tooltip />
                    <Line
                    type="monotone"
                    dataKey="count"
                    name="Findings"
                    stroke="#72f0b1"
                    strokeWidth={3}
                    dot={{ r: 4 }}
                    activeDot={{ r: 6 }}
                    />
                </LineChart>
                </ResponsiveContainer>
            )}
            </article>
      </div>
    </section>
  );
}

export default SecurityAnalytics;
