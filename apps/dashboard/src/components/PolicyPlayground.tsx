/**
 * NOSIH Dashboard — Policy Playground & Multi-Intercept Terminal.
 *
 * Allows executing custom or randomized multi-intercept requests with live terminal output,
 * expandable log inspection, decision badges, and log export.
 */

import { useState, useId } from "react";
import { interceptRequest } from "../api/client.js";
import type { InterceptRequest } from "../api/types.js";
import {
  generateRandomInterceptRequest,
  generateBatchInterceptRequests,
  SCENARIO_TEMPLATES,
} from "../utils/interceptScenarios.js";
import { useLogs, type InterceptLogItem } from "../contexts/LogsContext.js";

function utcTimestamp(): string {
  return new Date().toISOString().replace("Z", "000Z");
}

const SAMPLE_REQUEST: InterceptRequest = {
  requestId: "01905f7c-4e8a-7b3d-9a1e-f2c3d4e5f6b0",
  timestamp: utcTimestamp(),
  agentId: "4f1c9a7e6b3d2f8a5c0e1d9b7a6f4c2e8d1a3b5f7c9e0d2a4b6c8e1f3a5d7b9c",
  tokenId: "01905f7c-4e8a-7b3d-9a1e-f2c3d4e5f6b0",
  resource: "ros2:///cmd_vel",
  action: "publish",
  params: {
    twist: {
      linear: 0.2,
      angular: 0,
    },
  },
};

const COUNT_PRESETS = [1, 5, 10, 25, 50];

export function PolicyPlayground() {
  const customId = useId();
  const { logs, addLog, addLogs, clearLogs, downloadLogsJson, downloadLogsText } = useLogs();

  const [requestJson, setRequestJson] = useState<string>(
    JSON.stringify(SAMPLE_REQUEST, null, 2),
  );
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Runner controls
  const [interceptCount, setInterceptCount] = useState<number>(5);
  const [isCustomCount, setIsCustomCount] = useState(false);
  const [isRandomMode, setIsRandomMode] = useState(true);
  const [progress, setProgress] = useState<{ current: number; total: number } | null>(null);

  // Terminal UI state
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
  const [filterStatus, setFilterStatus] = useState<"all" | "allow" | "deny" | "escalate" | "error">("all");
  const [searchTerm, setSearchTerm] = useState("");

  /** Run a single or multiple intercepts */
  async function handleRunIntercepts() {
    setError(null);
    setLoading(true);

    const count = Math.min(Math.max(1, interceptCount || 1), 100);
    setProgress({ current: 0, total: count });

    const newLogs: InterceptLogItem[] = [];

    try {
      if (!isRandomMode && count === 1) {
        // Execute single custom request from editor
        const parsed = JSON.parse(requestJson) as InterceptRequest;
        const start = performance.now();
        let res: unknown = null;
        let status: InterceptLogItem["status"] = "allow";
        let tier: string | undefined;

        try {
          res = await interceptRequest(parsed);

          const resObj = res as Record<string, unknown>;
          if (resObj?.action === "deny") status = "deny";
          else if (resObj?.action === "escalate") status = "escalate";
          else status = "allow";

          if (typeof resObj?.assignedTier === "string") {
            tier = resObj.assignedTier;
          }
        } catch (callErr) {
          status = "error";
          const errMsg = callErr instanceof Error ? callErr.message : String(callErr);
          setError(errMsg);
          res = { error: errMsg };
        }

        const logItem: InterceptLogItem = {
          id: parsed.requestId || `req-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          durationMs: Math.round(performance.now() - start),
          request: parsed,
          response: res,
          status,
          tier,
        };

        addLog(logItem);
        setExpandedLogId(logItem.id);
      } else {
        // Run multiple random intercepts with live progress
        const requests = generateBatchInterceptRequests(count);

        for (let i = 0; i < requests.length; i++) {
          const req = requests[i];
          if (!req) continue;
          const start = performance.now();
          let res: unknown = null;
          let status: InterceptLogItem["status"] = "allow";
          let tier: string | undefined;
          let callError: string | undefined;

          try {
            res = await interceptRequest(req);
            const resObj = res as Record<string, unknown>;
            if (resObj?.action === "deny") status = "deny";
            else if (resObj?.action === "escalate") status = "escalate";
            else status = "allow";

            if (typeof resObj?.assignedTier === "string") {
              tier = resObj.assignedTier;
            }
          } catch (err) {
            status = "error";
            callError = err instanceof Error ? err.message : String(err);
            res = { error: callError };
          }

          const durationMs = Math.round(performance.now() - start);

          const logItem: InterceptLogItem = {
            id: req.requestId,
            timestamp: new Date().toLocaleTimeString(),
            durationMs,
            request: req,
            response: res,
            status,
            error: callError,
            tier,
          };

          newLogs.unshift(logItem);
          setProgress({ current: i + 1, total: count });

          // Small stagger for realistic streaming feel
          if (count > 1 && i < requests.length - 1) {
            await new Promise((r) => setTimeout(r, 60));
          }
        }

        addLogs(newLogs);
        if (newLogs.length > 0 && newLogs[0]) {
          setExpandedLogId(newLogs[0].id);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
      setProgress(null);
    }
  }

  function handleSelectScenario(index: number) {
    const req = generateRandomInterceptRequest(index);
    setRequestJson(JSON.stringify(req, null, 2));
    setError(null);
  }

  function resetTemplate() {
    setRequestJson(JSON.stringify({ ...SAMPLE_REQUEST, timestamp: utcTimestamp() }, null, 2));
    setError(null);
  }


  const toggleExpand = (id: string) => {
    setExpandedLogId((prev) => (prev === id ? null : id));
  };

  const filteredLogs = logs.filter((log) => {
    if (filterStatus !== "all" && log.status !== filterStatus) return false;
    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase();
      return (
        log.request.resource.toLowerCase().includes(term) ||
        log.request.action.toLowerCase().includes(term) ||
        log.id.toLowerCase().includes(term) ||
        (log.tier && log.tier.toLowerCase().includes(term))
      );
    }
    return true;
  });

  return (
    <section className="panel playground-panel">
      <div className="playground-header-row">
        <div>
          <h2 className="panel-title">
            Policy Playground & Intercept Runner
            <span className="panel-count">/v1/intercept</span>
          </h2>
          <p className="playground-help text-muted">
            Configure individual payloads or launch randomized test waves to test policy gates, CSML scores, and circuit breakers.
          </p>
        </div>

        {/* Quick Toolbar */}
        <div className="playground-header-actions">
          <div className="download-group">
            <button
              type="button"
              className="btn btn-download-compact"
              onClick={downloadLogsJson}
              disabled={logs.length === 0}
              title="Download execution logs as JSON"
            >
              <span>&#x21E9; JSON</span>
            </button>
            <button
              type="button"
              className="btn btn-download-compact"
              onClick={downloadLogsText}
              disabled={logs.length === 0}
              title="Download execution logs as Terminal Text"
            >
              <span>&#x21E9; .LOG</span>
            </button>
          </div>
        </div>
      </div>

      {/* Runner Config Bar */}
      <div className="runner-control-bar">
        <div className="runner-count-selector">
          <span className="control-label">Intercept Count:</span>
          <div className="preset-pill-group">
            {COUNT_PRESETS.map((cnt) => (
              <button
                key={cnt}
                type="button"
                className={`preset-pill ${!isCustomCount && interceptCount === cnt ? "active" : ""}`}
                onClick={() => {
                  setIsCustomCount(false);
                  setInterceptCount(cnt);
                }}
              >
                {cnt}x
              </button>
            ))}
            <button
              type="button"
              className={`preset-pill ${isCustomCount ? "active" : ""}`}
              onClick={() => setIsCustomCount(true)}
            >
              Custom
            </button>
          </div>

          {isCustomCount && (
            <input
              type="number"
              min={1}
              max={50}
              value={interceptCount}
              onChange={(e) => setInterceptCount(Math.max(1, parseInt(e.target.value) || 1))}
              className="runner-number-input"
              placeholder="1-50"
            />
          )}
        </div>

        <div className="runner-mode-toggle">
          <label className="toggle-label">
            <input
              type="checkbox"
              checked={isRandomMode}
              onChange={(e) => setIsRandomMode(e.target.checked)}
            />
            <span>Randomize Scenarios (T0-T3)</span>
          </label>
        </div>

        <div className="runner-action-buttons">
          <button
            type="button"
            className="btn btn-approve btn-run-intercept"
            onClick={handleRunIntercepts}
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner-icon">&#x21BB;</span>
                Running {progress ? `(${progress.current}/${progress.total})` : "..."}
              </>
            ) : (
              <>
                <span className="play-icon">&#x25B6;</span>
                Run {interceptCount} Intercept{interceptCount > 1 ? "s" : ""}
              </>
            )}
          </button>
        </div>
      </div>

      {/* Progress Bar during execution */}
      {loading && progress && (
        <div className="runner-progress-track">
          <div
            className="runner-progress-fill"
            style={{ width: `${(progress.current / progress.total) * 100}%` }}
          />
        </div>
      )}

      {/* Main Grid: Request Editor + Live Terminal Output */}
      <div className="playground-grid">
        {/* Left: Request Payload Composer */}
        <div className="composer-column">
          <div className="composer-header">
            <label className="playground-label" htmlFor="playground-request">
              Request Payload {isRandomMode ? "(Base / Preview)" : "(Active Payload)"}
            </label>

            {/* Quick Templates Selector */}
            <div className="scenario-presets">
              <label htmlFor={`${customId}-scenario-select`} className="preset-label">Template:</label>
              <select
                id={`${customId}-scenario-select`}
                className="scenario-select"
                onChange={(e) => handleSelectScenario(Number(e.target.value))}
                defaultValue=""
              >
                <option value="" disabled>Load preset...</option>
                {SCENARIO_TEMPLATES.map((item, idx) => (
                  <option key={idx} value={idx}>
                    [{item.tierHint.replace("_", " ")}] {item.resource} ({item.action})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <textarea
            id="playground-request"
            className="playground-textarea"
            value={requestJson}
            onChange={(e) => setRequestJson(e.target.value)}
            spellCheck={false}
          />

          <div className="playground-actions">
            <button
              type="button"
              className="btn btn-deny"
              onClick={resetTemplate}
              disabled={loading}
            >
              Reset Default
            </button>
            <button
              type="button"
              className="btn btn-secondary-outline"
              onClick={() => {
                const randomReq = generateRandomInterceptRequest();
                setRequestJson(JSON.stringify(randomReq, null, 2));
              }}
              disabled={loading}
            >
              &#x2684; Roll Random Payload
            </button>
          </div>
        </div>

        {/* Right: Interactive Terminal Console */}
        <div className="terminal-column">
          <div className="terminal-window">
            {/* Terminal Top Window Bar */}
            <div className="terminal-titlebar">
              <div className="window-dots">
                <span className="dot dot-red" />
                <span className="dot dot-yellow" />
                <span className="dot dot-green" />
              </div>
              <div className="terminal-title">
                <span className="terminal-prompt">$</span> nosih-gateway --watch intercept-stream
              </div>
              <div className="terminal-badges">
                <span className="terminal-badge-count">{logs.length} logged</span>
              </div>
            </div>

            {/* Terminal Filters Toolbar */}
            <div className="terminal-toolbar">
              <div className="terminal-filter-chips">
                {(["all", "allow", "deny", "escalate", "error"] as const).map((st) => (
                  <button
                    key={st}
                    type="button"
                    className={`terminal-chip chip-${st} ${filterStatus === st ? "active" : ""}`}
                    onClick={() => setFilterStatus(st)}
                  >
                    {st.toUpperCase()}
                  </button>
                ))}
              </div>

              <div className="terminal-search-box">
                <input
                  type="text"
                  placeholder="Filter resource / action..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="terminal-search-input"
                />
                {logs.length > 0 && (
                  <button
                    type="button"
                    className="terminal-clear-btn"
                    onClick={clearLogs}
                    title="Clear terminal logs"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>

            {/* Terminal Scrollable Logs Area */}
            <div className="terminal-body" role="log" aria-live="polite">
              {filteredLogs.length === 0 ? (
                <div className="terminal-empty">
                  <span className="terminal-cursor">_</span>
                  <p className="terminal-empty-text">
                    {logs.length === 0
                      ? "Ready for execution. Click 'Run Intercept' above to dispatch requests."
                      : "No logs match the current filter."}
                  </p>
                </div>
              ) : (
                filteredLogs.map((log) => {
                  const isExpanded = expandedLogId === log.id;
                  return (
                    <div
                      key={log.id}
                      className={`terminal-log-entry status-${log.status} ${isExpanded ? "expanded" : ""}`}
                    >
                      {/* Clickable Summary Row */}
                      <div
                        className="terminal-log-row"
                        onClick={() => toggleExpand(log.id)}
                        title="Click to expand/collapse details"
                      >
                        <span className="log-expand-icon">{isExpanded ? "▼" : "▶"}</span>
                        <span className="log-timestamp">{log.timestamp}</span>

                        <span className={`log-badge badge-${log.status}`}>
                          {log.status.toUpperCase()}
                        </span>

                        {log.tier && (
                          <span className="log-tier-tag">{log.tier}</span>
                        )}

                        <span className="log-resource" title={log.request.resource}>
                          {log.request.resource}
                        </span>

                        <span className="log-action">
                          {log.request.action}
                        </span>

                        <span className="log-latency">{log.durationMs}ms</span>
                      </div>

                      {/* Expandable Deep Inspection */}
                      {isExpanded && (
                        <div className="terminal-log-details">
                          <div className="details-meta-grid">
                            <div>
                              <span className="meta-key">Request ID:</span>{" "}
                              <code className="meta-val">{log.request.requestId}</code>
                            </div>
                            <div>
                              <span className="meta-key">Agent ID:</span>{" "}
                              <code className="meta-val">{log.request.agentId.slice(0, 16)}...</code>
                            </div>
                            {log.request.tokenId && (
                              <div>
                                <span className="meta-key">Token ID:</span>{" "}
                                <code className="meta-val">{log.request.tokenId.slice(0, 16)}...</code>
                              </div>
                            )}
                            <div>
                              <span className="meta-key">Execution Time:</span>{" "}
                              <span className="meta-val">{log.durationMs} ms</span>
                            </div>
                          </div>

                          <div className="details-json-grid">
                            <div className="json-column">
                              <div className="json-col-title">Request Payload</div>
                              <pre className="terminal-code-block">
                                {JSON.stringify(log.request, null, 2)}
                              </pre>
                            </div>
                            <div className="json-column">
                              <div className="json-col-title">Policy Decision Response</div>
                              <pre className="terminal-code-block">
                                {JSON.stringify(log.response, null, 2)}
                              </pre>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>

            {/* Terminal Footer Info */}
            <div className="terminal-footer">
              <span className="terminal-hint">
                Showing {filteredLogs.length} of {logs.length} logs &bull; Click any entry to inspect JSON
              </span>
              {error && <span className="terminal-err-hint">&#x26A0; {error}</span>}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
