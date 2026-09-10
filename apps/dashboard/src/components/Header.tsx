/**
 * NOSIH Dashboard — Header Component.
 *
 * Shows the NOSIH logo, connection status, health stats,
 * and the authenticated operator identity with logout.
 */

import { useState } from "react";
import type { HealthResponse } from "../api/types.js";
import { useAuth } from "../contexts/AuthContext.js";
import { useLogs } from "../contexts/LogsContext.js";

interface HeaderProps {
  health: HealthResponse | null;
  sseConnected: boolean;
  pendingCount: number;
}

export function Header({ health, sseConnected, pendingCount }: HeaderProps) {
  const { session, logout } = useAuth();
  const { logs, downloadLogsJson, downloadLogsText } = useLogs();
  const [downloadOpen, setDownloadOpen] = useState(false);

  return (
    <header className="header">
      <div className="header-left">
        <h1 className="logo">
          <span className="logo-icon">&#x1F6E1;</span>
          <span className="logo-text">NOSIH</span>
          <span className="logo-sub">Approval Dashboard</span>
        </h1>
      </div>

      <div className="header-center">
        {pendingCount > 0 && (
          <div className="pending-badge">
            <span className="badge-pulse" />
            <span className="badge-count">{pendingCount}</span>
            <span className="badge-label">pending</span>
          </div>
        )}
      </div>

      <div className="header-right">
        <div className={`status-dot ${sseConnected ? "connected" : "disconnected"}`} />
        <span className="status-label">
          {sseConnected ? "Live" : "Offline"}
        </span>

        {health && (
          <div className="health-stats">
            <span className="stat" title="Active tokens">
              <span className="stat-icon">&#x1F511;</span> {health.tokens}
            </span>
            <span className="stat" title="Ledger events">
              <span className="stat-icon">&#x1F4DC;</span> {health.ledgerEvents}
            </span>
            <span className="stat" title="Revoked tokens">
              <span className="stat-icon">&#x1F6AB;</span> {health.revokedTokens}
            </span>
          </div>
        )}

        {/* Top-Right Download Logs Option */}
        <div className="header-download-wrapper">
          <button
            type="button"
            className={`btn-header-download ${logs.length > 0 ? "has-logs" : ""}`}
            onClick={() => setDownloadOpen((v) => !v)}
            title={logs.length > 0 ? `Download ${logs.length} Intercept logs` : "No intercept logs yet"}
          >
            <span className="download-icon">&#x21E9;</span>
            <span className="download-label">Download Logs</span>
            {logs.length > 0 && <span className="download-pill">{logs.length}</span>}
          </button>

          {downloadOpen && (
            <div className="download-dropdown-menu">
              <div className="dropdown-header">
                <span>Export Intercept Logs</span>
                <span className="dropdown-count">{logs.length} entries</span>
              </div>
              <button
                type="button"
                className="dropdown-item"
                disabled={logs.length === 0}
                onClick={() => {
                  downloadLogsJson();
                  setDownloadOpen(false);
                }}
              >
                <span className="dropdown-item-icon">&#x1F4C4;</span>
                <div className="dropdown-item-text">
                  <strong>JSON Format</strong>
                  <small>Full payload with request & response objects</small>
                </div>
              </button>
              <button
                type="button"
                className="dropdown-item"
                disabled={logs.length === 0}
                onClick={() => {
                  downloadLogsText();
                  setDownloadOpen(false);
                }}
              >
                <span className="dropdown-item-icon">&#x1F4DD;</span>
                <div className="dropdown-item-text">
                  <strong>Terminal Log (.log)</strong>
                  <small>Formatted lines with timestamps & status</small>
                </div>
              </button>
            </div>
          )}
        </div>

        {session && (
          <div className="operator-badge">
            <span className="operator-icon">&#x1F464;</span>
            <span className="operator-name">{session.operatorName}</span>
            <button
              className="btn-logout"
              onClick={logout}
              title="Sign out"
            >
              &#x23FB;
            </button>
          </div>
        )}
      </div>
    </header>
  );
}

