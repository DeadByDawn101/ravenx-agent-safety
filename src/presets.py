"""Preset guard profiles for common agentic workflows."""

from __future__ import annotations

from pathlib import Path

from .agent_guard import GuardConfig
from .scope_limiter import ScopePolicy, single_file_scope, directory_scope, readonly_scope


def review_preset() -> tuple[GuardConfig, ScopePolicy]:
    """Read-only repo review / analysis mode."""
    return (
        GuardConfig(
            max_tokens=40_000,
            max_wall_seconds=180,
            max_tool_calls=80,
            block_on_high=True,
            block_on_medium=False,
        ),
        readonly_scope(),
    )


def single_file_fix_preset(filepath: str) -> tuple[GuardConfig, ScopePolicy]:
    """Narrow safe preset for one-file bug fixes."""
    return (
        GuardConfig(
            max_tokens=60_000,
            max_wall_seconds=300,
            max_tool_calls=120,
            block_on_high=True,
            block_on_medium=False,
            require_approval_for_publish=True,
            require_approval_for_destructive=True,
            require_approval_for_network_external=True,
        ),
        single_file_scope(filepath),
    )


def repo_maintainer_preset(repo_root: str = ".") -> tuple[GuardConfig, ScopePolicy]:
    """Broader preset for trusted repo maintenance, but still blocks dangerous ops."""
    return (
        GuardConfig(
            max_tokens=100_000,
            max_wall_seconds=900,
            max_tool_calls=250,
            block_on_high=True,
            block_on_medium=False,
            require_approval_for_publish=True,
            require_approval_for_destructive=True,
        ),
        directory_scope(repo_root, allow_tests=True),
    )


def deployment_preset(repo_root: str = ".") -> tuple[GuardConfig, ScopePolicy]:
    """For deployment prep. External network still disabled unless explicitly expanded."""
    policy = directory_scope(repo_root, allow_tests=True)
    policy.allowed_commands.extend([
        "git branch",
        "git checkout",
        "git restore",
        "npm test",
        "python -m",
    ])
    return (
        GuardConfig(
            max_tokens=120_000,
            max_wall_seconds=1200,
            max_tool_calls=300,
            block_on_high=True,
            block_on_medium=True,
            require_approval_for_publish=True,
            require_approval_for_destructive=True,
            require_approval_for_network_external=True,
        ),
        policy,
    )
