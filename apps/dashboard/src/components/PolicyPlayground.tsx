import { useState } from "react";
import { interceptRequest } from "../api/client.js";
import type { InterceptRequest } from "../api/types.js";

function utcTimestamp(): string {
  return new Date().toISOString().replace("Z", "000Z");
}

const SAMPLE_REQUEST: InterceptRequest = {
  requestId: "01905f7c-4e8a-7b3d-9a1e-f2c3d4e5f6b0",
  timestamp: utcTimestamp(),
  // Schema-valid development identifiers. Replace tokenId with an issued token
  // before testing an authorization decision.
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

export function PolicyPlayground() {
  const [requestJson, setRequestJson] = useState<string>(
    JSON.stringify(SAMPLE_REQUEST, null, 2),
  );
  const [responseJson, setResponseJson] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function runIntercept() {
    setError(null);
    setLoading(true);
    try {
      const parsed = JSON.parse(requestJson) as InterceptRequest;
      const result = await interceptRequest(parsed);
      setResponseJson(JSON.stringify(result, null, 2));
    } catch (err) {
      setResponseJson("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  function resetTemplate() {
    setRequestJson(JSON.stringify({ ...SAMPLE_REQUEST, timestamp: utcTimestamp() }, null, 2));
    setResponseJson("");
    setError(null);
  }

  return (
    <section className="panel playground-panel">
      <h2 className="panel-title">
        Policy Playground
        <span className="panel-count">/v1/intercept</span>
      </h2>

      <p className="playground-help text-muted">
        Paste or edit a request payload, then run it through the live policy engine.
        The template uses valid identifier formats; replace its tokenId with an issued
        token before testing an authorization decision.
      </p>

      <div className="playground-grid">
        <div>
          <label className="playground-label" htmlFor="playground-request">
            Request JSON
          </label>
          <textarea
            id="playground-request"
            className="playground-textarea"
            value={requestJson}
            onChange={(e) => setRequestJson(e.target.value)}
            spellCheck={false}
          />

          <div className="playground-actions">
            <button className="btn btn-approve" onClick={runIntercept} disabled={loading}>
              {loading ? "Running..." : "Run Intercept"}
            </button>
            <button className="btn btn-deny" onClick={resetTemplate} disabled={loading}>
              Reset Template
            </button>
          </div>
        </div>

        <div>
          <label className="playground-label" htmlFor="playground-response">
            Response
          </label>
          <textarea
            id="playground-response"
            className="playground-textarea playground-textarea-readonly"
            value={error ? `ERROR:\n${error}` : responseJson || "Run a request to see policy decision output."}
            readOnly
            spellCheck={false}
          />
        </div>
      </div>
    </section>
  );
}
