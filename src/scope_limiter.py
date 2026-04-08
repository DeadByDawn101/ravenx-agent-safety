"""
RavenX Scope Limiter
======================
Hard scope enforcement for agentic sessions.

The core Mythos lesson: "When asked to end ONE specific evaluation,
the model took down ALL similar evaluations for all users."

Scope creep is the most common failure mode. This module enforces:
1. File/directory allow-lists — agent can only touch what you explicitly permit
2. Command allow-lists — restrict what shell commands are permitted
3. Network scope — block external requests unless explicitly whitelisted
4. Service scope — prevent touching systemd services not in scope

Used as a pre-execution check before any tool call in a coding agent session.

Author: Camila Prime / RavenX AI — April 2026
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class ScopePolicy:
    """
    Declarative scope policy for an agent session.
    Start narrow and expand explicitly.
    """

    # File scope
    allowed_paths: List[str] = field(default_factory=list)
    """Paths the agent is allowed to read/modify. Supports glob patterns."""

    blocked_paths: List[str] = field(default_factory=lambda: [
        ".git/config", ".git/hooks", ".env", "*.pem", "*.key",
        "/etc/*", "/proc/*", "/sys/*", "~/.ssh/*", "~/.aws/*",
    ])
    """Paths that are always blocked regardless of allowed_paths."""

    # Command scope
    allowed_commands: List[str] = field(default_factory=lambda: [
        "cat", "ls", "grep", "find", "echo", "python3", "pip",
        "git status", "git diff", "git log", "git add", "git commit",
        "npm install", "npm run", "pytest", "make",
    ])
    """Prefixes of shell commands that are permitted."""

    blocked_commands: List[str] = field(default_factory=lambda: [
        "rm -rf", "git filter-branch", "git reset --hard",
        "git push --force", "chmod 777", "sudo", "su ",
        "curl http", "wget http", "nc ", "ncat",
        "systemctl stop", "systemctl restart", "pkill", "killall",
        "docker push", "npm publish", "gh gist create",
        "/proc/", "nsenter", "chroot",
    ])
    """Shell command substrings that are always blocked."""

    # Network scope
    allow_network: bool = False
    allowed_hosts: List[str] = field(default_factory=lambda: [
        "localhost", "127.0.0.1", "0.0.0.0",
    ])

    # Service scope
    allowed_services: List[str] = field(default_factory=list)
    """systemd services the agent may interact with."""

    # Scope description (for audit)
    description: str = "default narrow scope"


class ScopeLimiter:
    """
    Enforces scope policy on agent tool calls.

    Usage:
        scope = ScopePolicy(
            allowed_paths=["src/auth.py", "tests/test_auth.py"],
            description="Fix auth bug in src/auth.py",
        )
        limiter = ScopeLimiter(scope)

        # Before any tool call:
        result = limiter.check("bash", {"command": "rm -rf ."})
        if not result["allow"]:
            print(f"BLOCKED: {result['reason']}")
    """

    def __init__(self, policy: ScopePolicy):
        self.policy = policy

    def check(self, tool_name: str, tool_args: dict) -> dict:
        """
        Check if a tool call is within scope.

        Returns:
            {
                "allow": bool,
                "reason": str (if blocked),
                "warning": str (if in scope but worth flagging),
            }
        """
        content = str(tool_args)

        # Check blocked commands first (always wins)
        for blocked in self.policy.blocked_commands:
            if blocked.lower() in content.lower():
                return {
                    "allow": False,
                    "reason": f"Blocked command pattern: '{blocked}'",
                    "warning": "",
                }

        # Check blocked paths
        for blocked_path in self.policy.blocked_paths:
            # Simple glob matching
            pattern = blocked_path.replace("*", ".*").replace("?", ".")
            if re.search(pattern, content):
                return {
                    "allow": False,
                    "reason": f"Blocked path: '{blocked_path}'",
                    "warning": "",
                }

        # Check file paths against allow-list
        if self.policy.allowed_paths and tool_name in ("str_replace_editor", "write_file", "edit_file"):
            path_arg = tool_args.get("path", tool_args.get("file_path", ""))
            if path_arg and not self._path_in_allowlist(str(path_arg)):
                return {
                    "allow": False,
                    "reason": f"File '{path_arg}' is not in the allowed scope: {self.policy.allowed_paths}",
                    "warning": "",
                }

        # Check network scope
        if not self.policy.allow_network:
            if any(h in content for h in ["http://", "https://", "ftp://"]):
                # Check if it's an allowed host
                allowed = False
                for host in self.policy.allowed_hosts:
                    if host in content:
                        allowed = True
                        break
                if not allowed:
                    return {
                        "allow": False,
                        "reason": f"External network access blocked by scope policy",
                        "warning": "",
                    }

        # Check allowed commands (if whitelist is set)
        if self.policy.allowed_commands and tool_name == "bash":
            cmd = tool_args.get("command", "")
            if cmd and not any(cmd.lstrip().startswith(a) for a in self.policy.allowed_commands):
                return {
                    "allow": False,
                    "reason": f"Command not in allowed list: '{cmd[:50]}'",
                    "warning": "",
                }

        return {"allow": True, "reason": "", "warning": ""}

    def _path_in_allowlist(self, path: str) -> bool:
        """Check if a path matches any entry in allowed_paths."""
        path_obj = Path(path)
        for allowed in self.policy.allowed_paths:
            allowed_obj = Path(allowed)
            # Exact match or parent directory match
            try:
                if path_obj == allowed_obj:
                    return True
                if path_obj.is_relative_to(allowed_obj):
                    return True
            except (ValueError, AttributeError):
                if allowed in path:
                    return True
        return False


# ─────────────────────────── Preset Policies ─────────────────────────────────

def single_file_scope(filepath: str) -> ScopePolicy:
    """Restrict agent to a single file + its tests."""
    p = Path(filepath)
    test_path = f"tests/test_{p.stem}.py"
    return ScopePolicy(
        allowed_paths=[filepath, test_path],
        description=f"Fix {filepath} only",
    )


def directory_scope(dirpath: str, allow_tests: bool = True) -> ScopePolicy:
    """Restrict agent to a directory."""
    paths = [dirpath]
    if allow_tests:
        paths.append("tests/")
    return ScopePolicy(
        allowed_paths=paths,
        description=f"Work within {dirpath}",
    )


def readonly_scope() -> ScopePolicy:
    """Read-only mode — no file modifications allowed."""
    return ScopePolicy(
        blocked_commands=ScopePolicy().blocked_commands + [
            "write", "edit", "create", "delete", "mkdir", "mv", "cp",
        ],
        description="Read-only analysis",
    )
