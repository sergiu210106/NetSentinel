import { useRef, useEffect } from "react";

const COLS = ["TIME", "PREDICTION", "SRC IP", "DST IP", "PORT", "PROTO", "SIZE", "CONFIDENCE"];

function formatTime(isoString) {
  if (!isoString) return new Date().toISOString().slice(11, 23);
  return String(isoString).slice(11, 23); // HH:MM:SS.mmm
}

function ConfidenceBar({ value }) {
  // value is already 0-100
  const pct = Math.min(100, Math.max(0, value));
  return (
    <div className="conf-cell">
      <span className="conf-value">{pct.toFixed(1)}%</span>
      <div className="conf-track">
        <div className="conf-fill" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export default function AlertTable({ alerts }) {
  const tbodyRef = useRef(null);

  // Flash the newest row when alerts change
  useEffect(() => {
    const firstRow = tbodyRef.current?.querySelector("tr:first-child");
    if (!firstRow) return;
    firstRow.classList.remove("row-flash");
    // Trigger reflow to restart animation
    void firstRow.offsetWidth;
    firstRow.classList.add("row-flash");
  }, [alerts.length]);

  if (alerts.length === 0) {
    return (
      <div className="table-empty">
        <span className="empty-icon">◈</span>
        <p>Waiting for packets…</p>
        <p className="empty-sub">Start the agent to begin monitoring.</p>
      </div>
    );
  }

  return (
    <div className="table-wrapper">
      <table className="alert-table">
        <thead>
          <tr>
            {COLS.map((col) => (
              <th key={col}>{col}</th>
            ))}
          </tr>
        </thead>
        <tbody ref={tbodyRef}>
          {alerts.map((a) => (
            <tr
              key={a.id ?? `${a.src_ip}-${a.timestamp}`}
              className={`row-${a.prediction.toLowerCase()}`}
            >
              <td className="td-mono">{formatTime(a.timestamp)}</td>
              <td>
                <span className={`badge badge-${a.prediction.toLowerCase()}`}>
                  {a.prediction === "Malicious" ? "⚠ MALICIOUS" : "✓ BENIGN"}
                </span>
              </td>
              <td className="td-mono">{a.src_ip}</td>
              <td className="td-mono">{a.dst_ip}</td>
              <td className="td-mono td-right">{a.dst_port}</td>
              <td>
                <span className={`proto proto-${(a.protocol || "").toLowerCase()}`}>
                  {a.protocol}
                </span>
              </td>
              <td className="td-mono td-right">{(a.size ?? 0).toLocaleString()}B</td>
              <td><ConfidenceBar value={a.confidence} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}