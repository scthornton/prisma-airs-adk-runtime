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
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

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
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        profile_name: Optional[str] = None,
        api_base: Optional[str] = None,
        timeout: float = 30.0,
        fail_open: bool = False,
        block_message: str = "This request was blocked by security policy.",
    ):
        self.api_key = api_key or os.environ["AIRS_API_KEY"]
        self.profile_name = profile_name or os.environ["AIRS_API_PROFILE_NAME"]
        self.api_base = (api_base or os.environ.get("AIRS_API_BASE") or DEFAULT_API_BASE).rstrip("/")
        self.timeout = timeout
        self.fail_open = fail_open
        self.block_message = block_message

    # ---- core scan call -----------------------------------------------------

    async def _scan(self, content: dict) -> dict:
        """POST one content item to the AIRS sync scan API. Returns the verdict
        dict, or a synthetic block/allow on transport error per fail_open."""
        payload = {
            "contents": [content],
            "ai_profile": {"profile_name": self.profile_name},
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
        verdict = await self._scan(self._tool_event(tool, args))
        if self._is_block(verdict):
            return {"error": "Tool call blocked by security policy",
                    "airs_scan_id": verdict.get("scan_id")}
        return None

    async def after_tool(
        self, tool: Any, args: dict, tool_context: Any, tool_response: dict
    ) -> Optional[dict]:
        """Scan a tool result, as an AIRS tool_event with output. Return a dict to
        replace the result (e.g. on credential leakage / DLP in the output)."""
        verdict = await self._scan(self._tool_event(tool, args, tool_response))
        if self._is_block(verdict):
            return {"error": "Tool result withheld by security policy",
                    "airs_scan_id": verdict.get("scan_id")}
        return None

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
    def _tool_event(tool: Any, args: dict, result: Optional[dict] = None) -> dict:
        # AIRS only accepts ecosystem "mcp" for tool_events today; label the real
        # source via server_name / tool_invoked.
        event: dict = {
            "tool_event": {
                "metadata": {
                    "ecosystem": "mcp",
                    "method": "tools/call",
                    "server_name": "adk",
                    "tool_invoked": getattr(tool, "name", "unknown"),
                },
                "input": json.dumps(args or {}),
            }
        }
        if result is not None:
            event["tool_event"]["output"] = json.dumps(result)
        return event

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
