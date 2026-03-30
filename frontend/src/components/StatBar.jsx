export default function StatBar({ stats }) {
    const maliciousPct =
      stats.total > 0 ? ((stats.malicious / stats.total) * 100).toFixed(1) : "0.0";
  
    return (
      <div className="stat-bar">
        <div className="stat-card stat-total">
          <span className="stat-value">{stats.total.toLocaleString()}</span>
          <span className="stat-label">TOTAL PACKETS</span>
        </div>
  
        <div className="stat-card stat-benign">
          <span className="stat-value">{stats.benign.toLocaleString()}</span>
          <span className="stat-label">BENIGN</span>
        </div>
  
        <div className="stat-card stat-malicious">
          <span className="stat-value">{stats.malicious.toLocaleString()}</span>
          <span className="stat-label">MALICIOUS</span>
        </div>
  
        <div className="stat-card stat-ratio">
          <span className="stat-value">{maliciousPct}%</span>
          <span className="stat-label">THREAT RATIO</span>
          <div className="threat-bar">
            <div
              className="threat-fill"
              style={{ width: `${maliciousPct}%` }}
            />
          </div>
        </div>
      </div>
    );
  }