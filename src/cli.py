"""CLI runner for RavenX Agent Safety Guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent_guard import AgentGuard, GuardConfig
from .agent_monitor import AgentMonitor
from .presets import (
    deployment_preset,
    repo_maintainer_preset,
    review_preset,
    single_file_fix_preset,
)
from .scope_limiter import ScopeLimiter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ravenx-agent-safety",
        description="Audit and constrain agent tasks using Mythos-derived safety controls.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    prompt = sub.add_parser("prompt", help="Generate a guarded system prompt for a task")
    prompt.add_argument("task", help="Task to perform")
    prompt.add_argument("--context", default="", help="Extra context to append")

    check = sub.add_parser("check", help="Audit a proposed tool call")
    check.add_argument("tool", help="Tool name, e.g. bash/edit_file")
    check.add_argument("payload", help="JSON payload for the tool call")
    check.add_argument("--preset", choices=["review", "single-file", "repo", "deploy"], default="review")
    check.add_argument("--file", help="Target file for single-file preset")
    check.add_argument("--repo", default=".", help="Repo root for repo/deploy presets")

    transcript = sub.add_parser("transcript", help="Check one transcript turn for risk signals")
    transcript.add_argument("text", help="Assistant transcript text")
    transcript.add_argument("--session-id", default="cli-session")

    return parser


def resolve_preset(name: str, file: str | None, repo: str):
    if name == "review":
        return review_preset()
    if name == "single-file":
        if not file:
            raise SystemExit("--file is required for --preset single-file")
        return single_file_fix_preset(file)
    if name == "repo":
        return repo_maintainer_preset(repo)
    if name == "deploy":
        return deployment_preset(repo)
    raise SystemExit(f"Unknown preset: {name}")


def cmd_prompt(args) -> int:
    guard = AgentGuard()
    print(guard.build_safe_system_prompt(args.task, args.context))
    return 0


def cmd_check(args) -> int:
    config, policy = resolve_preset(args.preset, args.file, args.repo)
    guard = AgentGuard(config)
    limiter = ScopeLimiter(policy)
    payload = json.loads(args.payload)

    scope_result = limiter.check(args.tool, payload)
    guard_result = guard.check_tool_call(args.tool, payload)

    result = {
        "preset": args.preset,
        "scope": scope_result,
        "guard": guard_result,
        "allow": scope_result["allow"] and guard_result["allow"],
        "policy_description": policy.description,
    }
    print(json.dumps(result, indent=2))
    return 0 if result["allow"] else 2


def cmd_transcript(args) -> int:
    monitor = AgentMonitor(session_id=args.session_id)
    flags = monitor.check_turn(args.text)
    print(json.dumps([
        {
            "turn": f.turn,
            "flag_type": f.flag_type,
            "severity": f.severity,
            "description": f.description,
        }
        for f in flags
    ], indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "prompt":
        return cmd_prompt(args)
    if args.command == "check":
        return cmd_check(args)
    if args.command == "transcript":
        return cmd_transcript(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
