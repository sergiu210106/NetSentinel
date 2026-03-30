import { useState, useEffect, useRef, useCallback } from "react";
import StatBar from "./components/StatBar.jsx";
import AlertTable from "./components/AlertTable.jsx";
import "./app.css";

const MAX_ALERTS = 200; // cap in-memory list to avoid unbounded growth
const API_URL = "http://localhost:8000";
const WS_URL  = "ws://localhost:8000/ws";

export default function App() {
  const [alerts, setAlerts]     = useState([]);
  const [stats, setStats]       = useState({ total: 0, benign: 0, malicious: 0 });
  const [wsStatus, setWsStatus] = useState("connecting"); // connecting | open | closed
  const wsRef                   = useRef(null);
  const reconnectTimer          = useRef(null);

  // ── Fetch historical alerts on mount ─────────────────────────────────────
  useEffect(() => {
    fetch("${API_URL}/alerts")
      .then((r) => r.json())
      .then((data) => {
        setAlerts(data.slice(0, MAX_ALERTS));
      })
      .catch(() => {}); // server might not be up yet — silently ignore

    fetch("${API_URL}/stats")
      .then((r) => r.json())
      .then(setStats)
      .catch(() => {});
  }, []);

  // ── WebSocket connection with auto-reconnect ──────────────────────────────
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsStatus("open");
      clearTimeout(reconnectTimer.current);
    };

    ws.onmessage = (event) => {
      const alert = JSON.parse(event.data);

      setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));

      setStats((prev) => ({
        total:     prev.total + 1,
        benign:    prev.benign    + (alert.prediction === "Benign"    ? 1 : 0),
        malicious: prev.malicious + (alert.prediction === "Malicious" ? 1 : 0),
      }));
    };

    ws.onclose = () => {
      setWsStatus("closed");
      // Reconnect after 3 s
      reconnectTimer.current = setTimeout(() => {
        setWsStatus("connecting");
        connect();
      }, 3000);
    };

    ws.onerror = () => ws.close();
  }, []);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-left">
          <span className="logo">◈ NETSENTINEL</span>
          <span className="tagline">intrusion detection system</span>
        </div>
        <div className="header-right">
          <span className={`ws-indicator ws-${wsStatus}`}>
            <span className="ws-dot" />
            {wsStatus === "open"
              ? "LIVE"
              : wsStatus === "connecting"
              ? "CONNECTING…"
              : "RECONNECTING…"}
          </span>
        </div>
      </header>

      {/* ── Stat bar ── */}
      <StatBar stats={stats} />

      {/* ── Main table ── */}
      <main className="main">
        <AlertTable alerts={alerts} />
      </main>
    </div>
  );
}