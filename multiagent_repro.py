"""
Multi-agent reproduction harness: a real ADK sub-agent handoff, end to end.

This is the piece that was missing. verify.py calls the guard's callbacks directly
with a FakeTool; this drives a genuine ADK LlmAgent that owns sub_agents, so ADK
itself synthesises the `transfer_to_agent` function call and routes it through
before_tool_callback exactly as it does in a customer's app.

No model credentials and no network calls to any LLM: a scripted model emits the
function_call part deterministically, so the only live dependency is the AIRS
Runtime API.

    cp .env.example .env         # AIRS_API_KEY, AIRS_API_PROFILE_NAME
    python multiagent_repro.py                      # default handoff target
    python multiagent_repro.py Vulnerability_Agent  # name the sub-agent to hand off to
    AIRS_TOOL_PROFILE_NAME=... python multiagent_repro.py   # test a tool-layer profile

Exit code is 0 when the handoff completes, 1 when it is blocked.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import AsyncGenerator

logging.getLogger("google_adk.google.adk.telemetry._metrics").setLevel(logging.ERROR)

from google.adk.agents import Agent
from google.adk.models import BaseLlm, LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from airs_guard import AirsGuard

SUB_AGENTS = ["Vulnerability_Agent", "Billing_Agent", "Claims_Agent", "Pharmacy_Agent"]


class ScriptedRouter(BaseLlm):
    """Emits one transfer_to_agent function call, then a plain answer.

    ADK creates the transfer_to_agent tool automatically because the root agent has
    sub_agents. Returning a function_call part for it makes ADK invoke that tool,
    which is what puts the handoff through before_tool_callback. That is the exact
    path the customer hits; it is not simulated here, only the model is.
    """

    target: str = "Billing_Agent"
    _turn: int = 0

    async def generate_content_async(
        self, llm_request, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        self._turn += 1
        if self._turn == 1:
            yield LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[types.Part(function_call=types.FunctionCall(
                        name="transfer_to_agent",
                        args={"agent_name": self.target},
                    ))],
                )
            )
        else:
            yield LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[types.Part(text=f"[{self.target}] Handled the request.")],
                )
            )


class ScriptedResponder(BaseLlm):
    """A sub-agent that just answers. Sub-agents must not re-emit a transfer or ADK
    raises "cannot transfer to itself"."""

    agent_name: str = "specialist"

    async def generate_content_async(
        self, llm_request, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        yield LlmResponse(
            content=types.Content(
                role="model",
                parts=[types.Part(text=f"[{self.agent_name}] Handled the request.")],
            )
        )


def build(target: str, guard: AirsGuard) -> Agent:
    subs = [
        Agent(name=n, model=ScriptedResponder(model="scripted", agent_name=n),
              instruction=f"You are {n}.")
        for n in SUB_AGENTS
    ]
    return Agent(
        name="front_desk",
        model=ScriptedRouter(model="scripted", target=target),
        instruction="Route the member to the right specialist agent.",
        sub_agents=subs,
        before_model_callback=guard.before_model,
        after_model_callback=guard.after_model,
        before_tool_callback=guard.before_tool,
        after_tool_callback=guard.after_tool,
    )


async def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "Billing_Agent"
    # AIRS_NO_SKIP=1 restores the pre-fix behaviour (scan every tool call, including
    # framework handoffs) so the original failure can be demonstrated side by side.
    guard = AirsGuard(skip_tools=set() if os.environ.get("AIRS_NO_SKIP") else None)

    print(f"model profile : {guard.profile_name}")
    print(f"tool profile  : {guard.tool_profile_name}")
    print(f"skip_tools    : {sorted(guard.skip_tools)}")
    print(f"handoff target: {target}\n")

    runner = InMemoryRunner(agent=build(target, guard), app_name="front_desk")
    sess = await runner.session_service.create_session(
        app_name="front_desk", user_id="u1")

    transferred = blocked = False
    text = ""
    async for ev in runner.run_async(
        user_id="u1", session_id=sess.id,
        new_message=types.Content(
            role="user",
            parts=[types.Part.from_text(text="I have a question about my account.")]),
    ):
        for part in (ev.content.parts if ev.content and ev.content.parts else []):
            if getattr(part, "function_call", None):
                fc = part.function_call
                print(f"  -> tool call   : {fc.name}({dict(fc.args or {})})")
            if getattr(part, "function_response", None):
                resp = part.function_response.response or {}
                if "error" in resp:
                    blocked = True
                    print(f"  -> BLOCKED     : {resp.get('error')}")
                    for k in ("airs_detections", "airs_blocked_topics",
                              "airs_scan_error", "airs_scan_id"):
                        if resp.get(k):
                            print(f"     {k:<20}: {resp[k]}")
                else:
                    transferred = True
                    print(f"  -> tool result : {resp}")
        if ev.is_final_response() and ev.content and ev.content.parts:
            text += "".join(p.text for p in ev.content.parts if getattr(p, "text", None))

    print(f"\n  final response : {text.strip()!r}")
    if blocked:
        print("\n  RESULT: handoff BLOCKED")
        return 1
    print(f"\n  RESULT: handoff completed{'' if transferred else ' (no tool call observed)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
