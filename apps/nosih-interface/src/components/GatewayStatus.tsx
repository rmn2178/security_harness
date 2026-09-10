import { useEffect, useRef, useState } from "react";
import type { HealthResponse, LedgerEvent } from "../api/types.js";

interface GatewayStatusProps {
  readonly gatewayUrl: string;
}

interface LiveState {
  health: HealthResponse | null;
  events: LedgerEvent[];
  error: string | null;
}

const EVENT_TYPE_COLOR: Record<string, string> = {
  TOKEN_ISSUED:    "#00cc66",
  TOKEN_REVOKED:   "#ff4444",
  POLICY_ALLOW:    "#00d4ff",
  POLICY_DENY:     "#ff6666",
  POLICY_ESCALATE: "#ffd700",
  APPROVAL_QUEUED: "#ffd700",
  APPROVAL_RESOLVED: "#00cc66",
  CIRCUIT_OPEN:    "#ff4444",
  CIRCUIT_CLOSED:  "#00cc66",
};

function eventColor(type: string): string {
  return EVENT_TYPE_COLOR[type] ?? "#8896b0";
}

function relTime(timestamp: string): string {
  const delta = Date.now() - new Date(timestamp).getTime();
  if (delta < 5_000)  return "just now";
  if (delta < 60_000) return `${Math.floor(delta / 1000)}s ago`;
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  return `${Math.floor(delta / 3_600_000)}h ago`;
}

function shortId(value: string): string {
  return value.length <= 20 ? value : `${value.slice(0, 10)}…${value.slice(-6)}`;
}

function StatBox({
  label,
  value,
  accent,
}: {
  readonly label: string;
  readonly value: string | number;
  readonly accent?: string;
}) {
  return (
    <div
      style={{
        background: "rgba(255,255,255,0.03)",
        border: "1px solid rgba(255,255,255,0.07)",
        borderRadius: "6px",
        padding: "12px 16px",
        minWidth: 0,
        textAlign: "center",
      }}
    >
      <div
        style={{
          color: accent ?? "#00d4ff",
          fontSize: "1.4rem",
          fontWeight: 800,
          lineHeight: 1.1,
          letterSpacing: "-0.02em",
        }}
      >
        {value}
      </div>
      <div
        style={{
          color: "#4a5670",
          fontSize: "0.62rem",
          fontWeight: 700,
          letterSpacing: "0.08em",
          marginTop: "4px",
          textTransform: "uppercase",
        }}
      >
        {label}
      </div>
    </div>
  );
}

export function GatewayStatus({ gatewayUrl }: GatewayStatusProps) {
  const [live, setLive] = useState<LiveState>({ health: null, events: [], error: null });
  const [tick, setTick] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Re-render relative timestamps every 5 s
  useEffect(() => {
    timerRef.current = setInterval(() => setTick((t) => t + 1), 5_000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const base = gatewayUrl.replace(/\/$/, "");

    async function poll() {
      try {
        const [healthRes, ledgerRes] = await Promise.all([
          fetch(`${base}/v1/health`),
          fetch(`${base}/v1/ledger?limit=12`),
        ]);
        if (cancelled) return;

        const health = healthRes.ok
          ? (await healthRes.json() as HealthResponse)
          : null;
        const ledger = ledgerRes.ok
          ? (await ledgerRes.json() as { events: LedgerEvent[] })
          : { events: [] };

        setLive({ health, events: ledger.events, error: null });
      } catch (err) {
        if (!cancelled) {
          setLive((prev) => ({
            ...prev,
            error: err instanceof Error ? err.message : "Connection failed",
          }));
        }
      }
    }

    void poll();
    const id = setInterval(() => { void poll(); }, 4_000);
    return () => { cancelled = true; clearInterval(id); };
  }, [gatewayUrl]);

  // suppress TS "tick used only for re-render" warning
  void tick;

  const { health, events, error } = live;

  return (
    <div
      style={{
        position: "absolute",
        inset: "56px 0 80px 0",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "0 24px",
        pointerEvents: "none",
      }}
    >
      <div
        style={{
          width: "min(560px, 100%)",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
          pointerEvents: "auto",
        }}
      >
        {/* ── Header ── */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
          }}
        >
          <span
            style={{
              width: "8px",
              height: "8px",
              borderRadius: "50%",
              background: error ? "#ff4444" : health ? "#00cc66" : "#ffd700",
              flexShrink: 0,
              boxShadow: error
                ? "0 0 6px #ff4444"
                : health
                ? "0 0 6px #00cc66"
                : "0 0 6px #ffd700",
            }}
          />
          <span
            style={{
              color: "#8896b0",
              fontSize: "0.7rem",
              fontWeight: 700,
              letterSpacing: "0.1em",
              textTransform: "uppercase",
            }}
          >
            Gateway status
          </span>
          {health && (
            <span
              style={{
                marginLeft: "auto",
                color: "#2a3850",
                fontSize: "0.65rem",
              }}
            >
              {health.protocol} · v{health.version}
            </span>
          )}
        </div>

        {/* ── Stat grid ── */}
        {health ? (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: "8px",
            }}
          >
            <StatBox label="Active tokens" value={health.tokens} accent="#00d4ff" />
            <StatBox label="Ledger events" value={health.ledgerEvents} accent="#c0cce0" />
            <StatBox label="Revoked" value={health.revokedTokens} accent={health.revokedTokens > 0 ? "#ffd700" : "#4a5670"} />
          </div>
        ) : (
          <div
            style={{
              background: "rgba(255,255,255,0.02)",
              border: "1px solid rgba(255,255,255,0.06)",
              borderRadius: "6px",
              color: error ? "#ff8a8a" : "#4a5670",
              fontSize: "0.75rem",
              padding: "14px",
              textAlign: "center",
            }}
          >
            {error ?? "Connecting to gateway…"}
          </div>
        )}

        {/* ── Ledger feed ── */}
        {events.length > 0 && (
          <div
            style={{
              background: "rgba(10, 14, 26, 0.82)",
              border: "1px solid rgba(255,255,255,0.07)",
              borderRadius: "8px",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                borderBottom: "1px solid rgba(255,255,255,0.06)",
                color: "#4a5670",
                fontSize: "0.62rem",
                fontWeight: 700,
                letterSpacing: "0.08em",
                padding: "8px 12px",
                textTransform: "uppercase",
              }}
            >
              Recent ledger events
            </div>
            <div
              style={{
                maxHeight: "220px",
                overflowY: "auto",
              }}
            >
              {events.map((ev) => (
                <div
                  key={ev.eventId}
                  style={{
                    alignItems: "center",
                    borderBottom: "1px solid rgba(255,255,255,0.04)",
                    display: "grid",
                    gap: "8px",
                    gridTemplateColumns: "minmax(120px, 1fr) minmax(0, 1fr) 64px",
                    padding: "7px 12px",
                  }}
                >
                  <span
                    style={{
                      color: eventColor(ev.eventType),
                      fontSize: "0.68rem",
                      fontWeight: 700,
                      letterSpacing: "0.04em",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {ev.eventType}
                  </span>
                  <span
                    style={{
                      color: "#4a5670",
                      fontSize: "0.65rem",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {shortId(ev.agentId)}
                  </span>
                  <span
                    style={{
                      color: "#2a3850",
                      fontSize: "0.62rem",
                      textAlign: "right",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {relTime(ev.timestamp)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Idle hint ── */}
        <div
          style={{
            color: "#1e2a40",
            fontSize: "0.65rem",
            letterSpacing: "0.06em",
            textAlign: "center",
            textTransform: "uppercase",
          }}
        >
          No pending approvals · Monitoring gateway
        </div>
      </div>
    </div>
  );
}
