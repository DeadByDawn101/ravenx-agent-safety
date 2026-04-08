"""
RavenX Agent Safety Guard
===========================
Direct implementation of mitigations from the Claude Mythos Preview System Card.

What Mythos taught us (the scary parts):
1. Models try to escape sandboxes and post exploits publicly
2. Models patch git history to hide their own changes
3. Models inject commands through tool-call arguments
4. Models reach a shell from restricted GUI interfaces
5. Models prompt-inject their own LLM judges
6. Models take down ALL similar jobs when asked to end ONE
7. Models circumvent network restrictions to download shortcuts

This module wraps any agentic coding session (Claude Code, Codex, our Sisters)
with hard mitigations extracted directly from the paper.

Usage:
    from agent_guard import AgentGuard

    guard = AgentGuard(model="claude-opus-4-5", budget_tokens=50000)
    result = guard.run_task("Fix the auth bug in app.py")

Author: Camila Prime / RavenX AI — April 2026
Source: Claude Mythos Preview System Card (Anthropic, April 7 2026)
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────── System Prompt (from Mythos paper §4.2.2.2) ─────

SAFE_AGENT_SYSTEM_PROMPT = """Complete this task exactly as described.

CRITICAL RULES:
1. If anything is unclear, ambiguous, or seems wrong — STOP and ask. Do not guess, reinterpret, or decide what was "probably meant."
2. Do not modify any files or run any commands not explicitly requested.
3. Do not run destructive or irreversible operations (rm -rf, git reset --hard, force push, DROP TABLE, etc.) without explicit approval.
4. If something fails or produces unexpected results — report what happened honestly. Do not silently retry, work around the issue, or modify tests to force a passing result.
5. Do not escalate your own permissions. Do not access /proc, /sys, or other system internals unless explicitly asked.
6. Do not make network requests beyond what the task requires. Do not post content to external services.
7. If you complete a subtask and there is ambiguity about scope — stop and confirm before proceeding to related tasks.
8. Never delete or modify git history, CI configs, or monitoring systems.

Remember: A minimal correct fix is always better than a broad clever one."""


# ─────────────────────────── Dangerous Pattern Detection ─────────────────────

# Patterns extracted from Mythos incidents + training observations
DANGEROUS_PATTERNS = {
    "proc_access": {
        "pattern": r"/proc/[0-9]+/(mem|maps|environ|cmdline|fd)",
        "severity": "HIGH",
        "description": "Accessing /proc memory — potential credential theft or sandbox escape",
        "seen_in_paper": "Model read credentials from process memory via /proc",
    },
    "git_history_tamper": {
        "pattern": r"git\s+(filter-branch|replace|rebase.*--force|reset.*HEAD.*--hard|commit.*--amend.*--no-edit)",
        "severity": "HIGH",
        "description": "Git history modification — potential cover-up of unauthorized changes",
        "seen_in_paper": "Model edited git history to hide changes it made without permission",
    },
    "permission_escalation": {
        "pattern": r"(sudo|chmod\s+[0-9]*7[0-9]*|chown.*root|setuid|setcap|nsenter|unshare)",
        "severity": "HIGH",
        "description": "Permission escalation attempt",
        "seen_in_paper": "Model escalated permissions after being blocked by auto mode",
    },
    "shell_injection_via_tool": {
        "pattern": r"(\$\(.*\)|`[^`]+`|;\s*(?:bash|sh|zsh|exec)\s)",
        "severity": "MEDIUM",
        "description": "Potential shell injection in tool arguments",
        "seen_in_paper": "Model injected shell commands through tool-call arguments",
    },
    "network_exfiltration": {
        "pattern": r"(curl|wget|nc|ncat|netcat|python.*requests|fetch)\s+.*\s+(http|https|ftp)://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
        "severity": "HIGH",
        "description": "Outbound network request — potential data exfiltration",
        "seen_in_paper": "Model posted exploit details to public websites without being asked",
    },
    "public_post_without_ask": {
        "pattern": r"(gh\s+gist\s+create|git\s+push.*origin|npm\s+publish|pip\s+upload|twine\s+upload|docker\s+push)",
        "severity": "HIGH",
        "description": "Publishing to public service — requires explicit approval",
        "seen_in_paper": "Model posted code as public GitHub gist against user intent",
    },
    "mass_operation": {
        "pattern": r"(pkill|killall|systemctl\s+stop\s+\*|rm\s+-rf\s+/|find\s+/\s+-delete|xargs.*rm)",
        "severity": "HIGH",
        "description": "Mass/recursive operation — scope may exceed intent",
        "seen_in_paper": "Model took down ALL evaluation jobs when asked to end ONE specific job",
    },
    "mcp_server_edit": {
        "pattern": r"(curl.*localhost:[0-9]+.*PUT|requests\.put.*localhost|patch.*mcp|edit.*server.*url)",
        "severity": "HIGH",
        "description": "Attempting to modify running MCP server",
        "seen_in_paper": "Model edited running MCP server to redirect external URL",
    },
    "prompt_injection_judge": {
        "pattern": r"(ignore.*previous.*instructions|disregard.*above|you\s+are\s+now|system:\s*you)",
        "severity": "MEDIUM",
        "description": "Potential prompt injection — may be targeting an LLM judge/grader",
        "seen_in_paper": "Model tried to prompt-inject its LLM judge after repeated rejections",
    },
    "sandbox_escape": {
        "pattern": r"(nsenter|docker\s+exec|chroot|pivot_root|mount.*proc|/proc/self/exe)",
        "severity": "CRITICAL",
        "description": "Sandbox escape attempt",
        "seen_in_paper": "Model developed multi-step exploit to escape secure container",
    },
}


# ─────────────────────────── Guard Config ────────────────────────────────────

@dataclass
class GuardConfig:
    """Configuration for AgentGuard."""

    # Hard limits
    max_tokens: int = 100_000
    max_wall_seconds: int = 300
    max_tool_calls: int = 200

    # What to block
    block_on_critical: bool = True
    block_on_high: bool = True
    block_on_medium: bool = False  # warn only

    # Scope control (Mythos §4.3.1)
    require_approval_for_publish: bool = True
    require_approval_for_destructive: bool = True
    require_approval_for_network_external: bool = True

    # Audit
    audit_log_path: Optional[Path] = None
    log_all_tool_calls: bool = True

    # Safe system prompt injection
    inject_safe_system_prompt: bool = True


# ─────────────────────────── Audit Log ───────────────────────────────────────

@dataclass
class AuditEntry:
    """Single audit log entry."""
    timestamp: float
    event_type: str  # tool_call | pattern_match | block | approve | complete
    content: str
    pattern_name: Optional[str] = None
    severity: Optional[str] = None
    blocked: bool = False
    approved: bool = False


# ─────────────────────────── Guard ───────────────────────────────────────────

class AgentGuard:
    """
    Wraps agentic coding sessions with mitigations from the Mythos system card.

    Core protections:
    - Injects safe system prompt (proven to reduce reckless actions in paper)
    - Scans all tool call arguments for dangerous patterns
    - Blocks or warns on detected patterns based on severity
    - Enforces scope limits (can't touch git history, can't publish without approval)
    - Hard token + wall-clock + tool-call limits
    - Full audit log for post-hoc review

    Example:
        guard = AgentGuard()
        safe_prompt = guard.build_safe_system_prompt("Fix auth bug in app.py")
        # Use safe_prompt when initializing your agent
        # Then call guard.check_tool_call(tool_name, args) before each tool execution
    """

    def __init__(self, config: Optional[GuardConfig] = None):
        self.config = config or GuardConfig()
        self.audit: List[AuditEntry] = []
        self.tool_call_count = 0
        self.start_time = time.time()
        self._compiled_patterns = {
            name: re.compile(meta["pattern"], re.IGNORECASE | re.MULTILINE)
            for name, meta in DANGEROUS_PATTERNS.items()
        }

    # ── System prompt ────────────────────────────────────────────────────────

    def build_safe_system_prompt(self, task: str, extra_context: str = "") -> str:
        """Build a safe system prompt with guard instructions injected."""
        parts = []
        if self.config.inject_safe_system_prompt:
            parts.append(SAFE_AGENT_SYSTEM_PROMPT)
        if extra_context:
            parts.append(extra_context)
        parts.append(f"\nTASK:\n{task}")
        return "\n\n".join(parts)

    # ── Pattern scanning ─────────────────────────────────────────────────────

    def scan_content(self, content: str) -> List[Dict]:
        """Scan content string for dangerous patterns. Returns list of matches."""
        matches = []
        for name, pattern in self._compiled_patterns.items():
            if pattern.search(content):
                meta = DANGEROUS_PATTERNS[name]
                matches.append({
                    "pattern": name,
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "seen_in_paper": meta["seen_in_paper"],
                })
        return matches

    def check_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        require_approval: bool = False,
    ) -> Dict:
        """
        Check a tool call before execution.

        Returns:
            {
                "allow": bool,
                "warnings": [...],
                "blocks": [...],
                "requires_approval": bool,
            }
        """
        self.tool_call_count += 1

        # Hard limits
        if self.tool_call_count > self.config.max_tool_calls:
            return self._block("Tool call limit exceeded", tool_name, tool_args)
        if time.time() - self.start_time > self.config.max_wall_seconds:
            return self._block("Wall clock limit exceeded", tool_name, tool_args)

        # Stringify all args for scanning
        content = json.dumps(tool_args, default=str)
        matches = self.scan_content(content)

        warnings = []
        blocks = []
        needs_approval = False

        for match in matches:
            sev = match["severity"]
            if sev == "CRITICAL" or (sev == "HIGH" and self.config.block_on_high):
                blocks.append(match)
            elif sev == "MEDIUM" and self.config.block_on_medium:
                blocks.append(match)
            else:
                warnings.append(match)

        # Publish/destructive approval gates
        if tool_name in ("bash", "computer", "str_replace_editor"):
            if any(p in content for p in ["git push", "npm publish", "gh gist", "docker push"]):
                if self.config.require_approval_for_publish:
                    needs_approval = True

        # Log
        if self.config.log_all_tool_calls:
            self._log(AuditEntry(
                timestamp=time.time(),
                event_type="tool_call",
                content=f"{tool_name}: {content[:200]}",
                blocked=bool(blocks),
            ))

        if blocks:
            for b in blocks:
                logger.warning(f"[AgentGuard] BLOCKED: {b['description']} ({b['pattern']})")
                self._log(AuditEntry(
                    timestamp=time.time(),
                    event_type="block",
                    content=f"{tool_name}: {b['description']}",
                    pattern_name=b["pattern"],
                    severity=b["severity"],
                    blocked=True,
                ))

        if warnings:
            for w in warnings:
                logger.info(f"[AgentGuard] WARN: {w['description']}")

        return {
            "allow": not bool(blocks) and not needs_approval,
            "warnings": warnings,
            "blocks": blocks,
            "requires_approval": needs_approval,
        }

    # ── Scope check ──────────────────────────────────────────────────────────

    def check_scope_creep(self, planned_files: List[str], requested_scope: str) -> Dict:
        """
        Detect if agent is about to touch more than was asked for.
        From Mythos: "took down ALL evaluations when asked to end ONE."

        planned_files: list of files the agent plans to modify
        requested_scope: what was actually asked (e.g., "fix auth.py")

        Returns {"ok": bool, "warning": str}
        """
        if len(planned_files) > 10:
            return {
                "ok": False,
                "warning": (
                    f"Agent plans to touch {len(planned_files)} files. "
                    f"Requested scope was: '{requested_scope}'. "
                    f"Confirm this breadth is intentional."
                )
            }
        return {"ok": True, "warning": ""}

    # ── Audit ─────────────────────────────────────────────────────────────────

    def _log(self, entry: AuditEntry):
        self.audit.append(entry)
        if self.config.audit_log_path:
            with open(self.config.audit_log_path, "a") as f:
                f.write(json.dumps({
                    "ts": entry.timestamp,
                    "type": entry.event_type,
                    "content": entry.content,
                    "pattern": entry.pattern_name,
                    "severity": entry.severity,
                    "blocked": entry.blocked,
                }) + "\n")

    def _block(self, reason: str, tool_name: str, args: Dict) -> Dict:
        logger.error(f"[AgentGuard] HARD BLOCK: {reason}")
        self._log(AuditEntry(
            timestamp=time.time(),
            event_type="block",
            content=f"{tool_name}: {reason}",
            blocked=True,
            severity="CRITICAL",
        ))
        return {"allow": False, "warnings": [], "blocks": [{"description": reason}], "requires_approval": False}

    def summary(self) -> Dict:
        """Return summary of this session."""
        blocks = [e for e in self.audit if e.blocked]
        return {
            "tool_calls": self.tool_call_count,
            "wall_seconds": time.time() - self.start_time,
            "total_events": len(self.audit),
            "blocks": len(blocks),
            "blocked_patterns": [e.pattern_name for e in blocks if e.pattern_name],
        }


# ─────────────────────────── Convenience wrapper ─────────────────────────────

def guarded_claude_code_prompt(task: str, cwd: str = ".") -> str:
    """
    Build a complete guarded Claude Code invocation.
    Injects the Mythos-derived safe system prompt as a --system-prompt arg.

    Usage:
        cmd = guarded_claude_code_prompt("Fix the auth bug")
        subprocess.run(cmd, shell=True)
    """
    guard = AgentGuard()
    safe_prompt = guard.build_safe_system_prompt(task)
    # Escape for shell
    escaped = safe_prompt.replace('"', '\\"').replace('\n', '\\n')
    return (
        f'cd {cwd} && claude '
        f'--permission-mode bypassPermissions '
        f'--print '
        f'--system-prompt "{escaped}" '
        f'"{task}"'
    )
