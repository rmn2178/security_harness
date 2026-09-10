"""
OpenAI Agents SDK + NOSIH governance flow example.

Demonstrates:
1) pre-tool-call authorization
2) escalation suspend/resume via approval resolver
3) evidence lookup for the request

Run:
  python examples/openai_agents_governance_flow.py
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from nosih import (
    ApprovalResolution,
    GatewayClient,
    GatewayConfig,
    OpenAIAgentsGovernanceAdapter,
    NosihApprovalDeniedError,
    NosihApprovalRequiredError,
    NosihApprovalTimeoutError,
    NosihDeniedError,
    NosihRequest,
)


async def main() -> None:
    # Assumes local gateway-server running (see repo compose stacks).
    config = GatewayConfig(
        base_url="http://localhost:3100",
        token="dev-local-key",
        timeout=10,
        max_retries=2,
        retry_backoff_ms=150,
    )

    async with GatewayClient(config) as client:
        adapter = OpenAIAgentsGovernanceAdapter(client)

        request = NosihRequest(
            request_id="01905f7c-4e8a-7b3d-9a1e-f2c3d4e5f7a1",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "000Z",
            agent_id="openai-agents-worker",
            token_id="replace-with-valid-token-id",
            resource="mcp://warehouse/moveRobot",
            action="call",
            params={"robotId": "amr-17", "destination": "A-12"},
            execution_context={
                "deploymentProfile": "warehouse-amr",
                "bridgeProtocol": "a2a",
                "siteId": "warehouse-west",
            },
        )

        async def operator_resolver(_req: NosihRequest, decision):
            # Plug your human-in-the-loop workflow here (UI, pager, ticket, etc).
            if decision.assigned_tier.value in ("T2_act", "T3_commit"):
                return ApprovalResolution(
                    status="approved",
                    by="operator@warehouse-west",
                    reason="Shift lead approved dispatch",
                )
            return ApprovalResolution(status="approved", by="system")

        try:
            decision = await adapter.authorize_tool_call(
                request,
                on_escalation=operator_resolver,
                approval_timeout_s=30.0,
            )
            print("governance decision:", decision.action, "tier=", decision.assigned_tier.value)

            # Tool execution would run here in a real OpenAI Agents tool function.
            print("tool execution permitted -> execute downstream action")

            evidence = await adapter.evidence_for_request(request.request_id, limit=200)
            print("evidence events for request:", len(evidence))
            for evt in evidence[:5]:
                print(" -", evt.event_type, evt.event_id)

        except NosihDeniedError as e:
            print("DENIED:", e.policy_violated, e.reason)
        except NosihApprovalRequiredError as e:
            print("ESCALATED:", e.required_tier.value, "request_id=", e.approval_request_id)
        except NosihApprovalTimeoutError as e:
            print("TIMEOUT:", e.approval_request_id, "after", e.timeout_s, "seconds")
        except NosihApprovalDeniedError as e:
            print("APPROVAL DENIED:", e.approval_request_id, e.reason)


if __name__ == "__main__":
    asyncio.run(main())

