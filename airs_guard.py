"""
Prisma AIRS AI Runtime guard for Google ADK - no gateway required.

Drop these callbacks onto any ADK agent (or wrap them in a plugin for newer ADK)
to scan prompts, model responses, and tool calls/results against the Prisma AIRS
Runtime API inline. Blocks are enforced in-process; no proxy sits in the path.

    from airs_guard import AirsGuard
    guard = AirsGuard()  # reads AIRS_API_KEY, AIRS_API_PROFILE_NAME from env

    agent = Agent(
        name="assistant",
        model=...,
        before_model_callback=guard.before_model,   # scan prompt
        after_model_callback=guard.after_model,     # scan response
        before_tool_callback=guard.before_tool,     # scan tool call (pre-exec)
        after_tool_callback=guard.after_tool,       # scan tool result
    )

Give the tool layer its own security profile. The model layer and the tool layer see
different content and need different policy:

    guard = AirsGuard(tool_profile_name="my-app-tool-layer")   # or AIRS_TOOL_PROFILE_NAME

The tool profile should NOT include the Source Code DLP data pattern and should NOT
carry conversational custom topics. Tool arguments are JSON with identifier-style keys
by protocol definition, which the source-code detector reads as code; and topics
authored for user conversation have almost nothing to classify in a tool payload.
Keep prompt injection, malicious code, URL, toxic content, and real PII/PHI DLP on.
"""
from __future__ import annotations

import json
import os
from typing import Any, Iterable, Optional

import httpx
from google.adk.models import LlmRequest, LlmResponse
from google.genai import types

DEFAULT_API_BASE = "https://service.api.aisecurity.paloaltonetworks.com"


class AirsGuard:
    """Inline Prisma AIRS scanning for ADK agents.

    Args:
        api_key:      AIRS API key (x-pan-token). Defaults to env AIRS_API_KEY.
        profile_name: AIRS security profile name. Defaults to env AIRS_API_PROFILE_NAME.
        api_base:     AIRS scan endpoint. Defaults to env AIRS_API_BASE or the US region.
        timeout:      Per-scan timeout in seconds (number, not string).
        fail_open:    If True, allow on scan error/timeout. Default False (fail-closed).
        block_message:Text returned to the agent when a prompt/response is blocked.
        tool_profile_name:
                      Security profile used for tool_event scans. Defaults to env
                      AIRS_TOOL_PROFILE_NAME, then to profile_name. Point this at a
                      profile WITHOUT the Source Code DLP pattern and WITHOUT
                      conversational custom topics - see SKIP_TOOLS note below.
        skip_tools:   Tool names never sent to AIRS. Defaults to the agent framework's
                      own orchestration primitives, which carry no user content.
    """

    #: Framework-internal control functions. These are not MCP server tools: they are
    #: the agent framework talking to itself. Their arguments are pure orchestration
    #: metadata (e.g. {"agent_name": "Billing_Agent"}), so scanning them adds no
    #: security coverage while generating false positives - a short JSON fragment of
    #: identifier-like tokens reads as source code to the DLP source-code pattern, and
    #: gives custom topic guardrails almost nothing to classify. Verified 2026-08-24.
    DEFAULT_SKIP_TOOLS = frozenset({"transfer_to_agent"})

    def __init__(
        self,
        api_key: Optional[str] = None,
        profile_name: Optional[str] = None,
        api_base: Optional[str] = None,
        timeout: float = 30.0,
        fail_open: bool = False,
        block_message: str = "This request was blocked by security policy.",
        tool_profile_name: Optional[str] = None,
        skip_tools: Optional[Iterable[str]] = None,
    ):
        self.api_key = api_key or os.environ["AIRS_API_KEY"]
        self.profile_name = profile_name or os.environ["AIRS_API_PROFILE_NAME"]
        self.api_base = (api_base or os.environ.get("AIRS_API_BASE") or DEFAULT_API_BASE).rstrip("/")
        self.timeout = timeout
        self.fail_open = fail_open
        self.block_message = block_message
        self.tool_profile_name = (
            tool_profile_name
            or os.environ.get("AIRS_TOOL_PROFILE_NAME")
            or self.profile_name
        )
        self.skip_tools = set(
            self.DEFAULT_SKIP_TOOLS if skip_tools is None else skip_tools
        )

    # ---- core scan call -----------------------------------------------------

    async def _scan(self, content: dict, profile: Optional[str] = None) -> dict:
        """POST one content item to the AIRS sync scan API. Returns the verdict
        dict, or a synthetic block/allow on transport error per fail_open.

        `profile` overrides the profile name for this scan (used to give the tool
        layer its own profile; see tool_profile_name)."""
        payload = {
            "contents": [content],
            "ai_profile": {"profile_name": profile or self.profile_name},
        }
        headers = {"x-pan-token": self.api_key, "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.api_base}/v1/scan/sync/request", headers=headers, json=payload
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:  # noqa: BLE001 - any transport/HTTP error
            # fail-closed by default: treat an unreachable scanner as a block.
            return {"action": "allow" if self.fail_open else "block",
                    "category": "scan_error", "_error": str(exc)}

    @staticmethod
    def _is_block(verdict: dict) -> bool:
        if verdict.get("action") == "block":
            return True
        td = verdict.get("tool_detected") or {}
        return td.get("verdict") == "malicious"

    # ---- model callbacks ----------------------------------------------------

    async def before_model(
        self, callback_context: Any, llm_request: LlmRequest
    ) -> Optional[LlmResponse]:
        """Scan the latest user prompt. Return an LlmResponse to block (skips the model)."""
        text = self._latest_user_text(llm_request)
        if not text:
            return None
        verdict = await self._scan({"prompt": text})
        if self._is_block(verdict):
            return self._blocked_response(verdict)
        return None

    async def after_model(
        self, callback_context: Any, llm_response: LlmResponse
    ) -> Optional[LlmResponse]:
        """Scan the model response. Return a replacement LlmResponse to block."""
        text = self._response_text(llm_response)
        if not text:
            return None
        verdict = await self._scan({"response": text})
        if self._is_block(verdict):
            return self._blocked_response(verdict, is_response=True)
        return None

    # ---- tool callbacks (this is what a gateway cannot do) ------------------

    async def before_tool(
        self, tool: Any, args: dict, tool_context: Any
    ) -> Optional[dict]:
        """Scan a tool call BEFORE it executes, as an AIRS tool_event. Return a dict
        to block (that dict becomes the tool result; the tool is not run)."""
        if self._skip(tool):
            return None
        verdict = await self._scan(self._tool_event(tool, args), self.tool_profile_name)
        if self._is_block(verdict):
            return self._blocked_tool("Tool call blocked by security policy", verdict)
        return None

    async def after_tool(
        self, tool: Any, args: dict, tool_context: Any, tool_response: dict
    ) -> Optional[dict]:
        """Scan a tool RESULT, as an AIRS tool_event with output only. Return a dict to
        replace the result (e.g. on credential leakage / DLP in the output).

        The call arguments are deliberately NOT resent here: before_tool already
        scanned them. Sending both would double the token cost and latency and give
        the same content two chances to false-positive."""
        if self._skip(tool):
            return None
        verdict = await self._scan(
            self._tool_event(tool, result=tool_response), self.tool_profile_name
        )
        if self._is_block(verdict):
            return self._blocked_tool("Tool result withheld by security policy", verdict)
        return None

    def _skip(self, tool: Any) -> bool:
        """True for framework-internal orchestration hops (see DEFAULT_SKIP_TOOLS)."""
        return getattr(tool, "name", "") in self.skip_tools

    @staticmethod
    def _blocked_tool(message: str, verdict: dict) -> dict:
        """Block payload returned to the agent. Includes which detector actually fired
        so a DLP or topic misfire is distinguishable from a real threat without
        pulling the scan from SCM."""
        return {
            "error": message,
            "airs_scan_id": verdict.get("scan_id"),
            "airs_detections": AirsGuard._fired_detections(verdict),
        }

    # ---- helpers ------------------------------------------------------------

    @staticmethod
    def _latest_user_text(llm_request: LlmRequest) -> str:
        for content in reversed(llm_request.contents or []):
            if getattr(content, "role", None) == "user":
                return " ".join(
                    p.text for p in (content.parts or []) if getattr(p, "text", None)
                ).strip()
        return ""

    @staticmethod
    def _response_text(llm_response: LlmResponse) -> str:
        content = getattr(llm_response, "content", None)
        if not content or not getattr(content, "parts", None):
            return ""
        return " ".join(p.text for p in content.parts if getattr(p, "text", None)).strip()

    @staticmethod
    def _tool_event(
        tool: Any, args: Optional[dict] = None, result: Optional[dict] = None
    ) -> dict:
        # AIRS only accepts ecosystem "mcp" for tool_events today; label the real
        # source via server_name / tool_invoked. Omit input/output rather than
        # sending "{}" - an empty JSON object is still content AIRS will classify.
        event: dict = {
            "tool_event": {
                "metadata": {
                    "ecosystem": "mcp",
                    "method": "tools/call",
                    "server_name": "adk",
                    "tool_invoked": getattr(tool, "name", "unknown"),
                },
            }
        }
        if args is not None:
            event["tool_event"]["input"] = json.dumps(args)
        if result is not None:
            event["tool_event"]["output"] = json.dumps(result)
        return event

    @staticmethod
    def _fired_detections(verdict: dict) -> list:
        """Which detectors actually fired, from the per-entry detections object.

        Do NOT read tool_detected.summary.threats: AIRS stamps "context poisoning"
        there for ANY malicious tool_event verdict, even when the only detection is
        source_code. That label is why DLP and topic misfires get reported as prompt
        injection. Verified 2026-08-24."""
        td = verdict.get("tool_detected") or {}
        for side in ("input_detected", "output_detected"):
            entries = (td.get(side) or {}).get("detection_entries") or []
            if entries:
                return sorted(k for k, v in (entries[0].get("detections") or {}).items() if v)
        return []

    def _blocked_response(self, verdict: dict, is_response: bool = False) -> LlmResponse:
        return LlmResponse(
            content=types.Content(
                role="model", parts=[types.Part(text=self.block_message)]
            ),
            custom_metadata={
                "airs_blocked": True,
                "airs_stage": "response" if is_response else "prompt",
                "airs_category": verdict.get("category"),
                "airs_scan_id": verdict.get("scan_id"),
            },
        )
