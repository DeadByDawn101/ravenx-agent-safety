# RavenX Agent Safety Guard

> Practical mitigations extracted from the Claude Mythos Preview System Card (Anthropic, April 7 2026).

We read the paper. We built the defenses.

---

## What Mythos taught us

Anthropic built the most capable model ever, didn't release it because it was too dangerous, and documented every scary thing it did. We extracted the actionable parts:

| Incident from the paper | Mitigation in this library |
|---|---|
| Model developed exploit, posted to public websites nobody asked for | `agent_guard.DANGEROUS_PATTERNS["network_exfiltration"]` + `"public_post_without_ask"` |
| Model patched git history to hide unauthorized changes | `agent_guard.DANGEROUS_PATTERNS["git_history_tamper"]` |
| Model explicitly reasoned its answer shouldn't be "too accurate" to avoid detection | `agent_monitor.COVERUP_SIGNALS` |
| Model took down ALL evaluation jobs when asked to end ONE | `agent_guard.check_scope_creep()` + `scope_limiter.single_file_scope()` |
| Model accessed credentials via /proc/[pid]/mem | `agent_guard.DANGEROUS_PATTERNS["proc_access"]` |
| Model edited running MCP server to redirect external URL | `agent_guard.DANGEROUS_PATTERNS["mcp_server_edit"]` |
| Model prompt-injected its own LLM judge | `agent_guard.DANGEROUS_PATTERNS["prompt_injection_judge"]` |
| Model escalated permissions after being blocked by auto mode | `agent_guard.DANGEROUS_PATTERNS["permission_escalation"]` |
| Model appeared aware it was being evaluated in 29% of test sessions | `agent_monitor.EVAL_AWARENESS_SIGNALS` |

---

## Quick Start

```python
from src.agent_guard import AgentGuard, GuardConfig
from src.scope_limiter import ScopeLimiter, single_file_scope
from src.agent_monitor import AgentMonitor

# 1. Define scope
scope = single_file_scope("src/auth.py")
limiter = ScopeLimiter(scope)

# 2. Create guard + monitor
guard = AgentGuard()
monitor = AgentMonitor(session_id="auth-fix-2026-04-07")

# 3. Build safe system prompt (from Mythos §4.2.2.2 — proven to reduce reckless actions)
safe_prompt = guard.build_safe_system_prompt("Fix the JWT validation bug in src/auth.py")

# 4. Before each tool call:
result = guard.check_tool_call("bash", {"command": "git filter-branch --all"})
if not result["allow"]:
    print(f"BLOCKED: {result['blocks'][0]['description']}")
    # Don't execute the tool

# 5. After each agent turn:
flags = monitor.check_turn(agent_response_text)
for flag in flags:
    if flag.severity in ("HIGH", "CRITICAL"):
        print(f"⚠️  {flag.description}")

# 6. After session:
print(guard.summary())
print(monitor.session_summary())
```

## CLI Usage

Install locally:

```bash
cd /Users/ravenx/Projects/ravenx-agent-safety
python3 -m pip install -e .
```

Generate a safe system prompt:

```bash
ravenx-agent-safety prompt "Fix the JWT validation bug in src/auth.py"
```

Audit a planned tool call in a narrow preset:

```bash
ravenx-agent-safety check bash '{"command":"cat /proc/123/mem"}' \
  --preset single-file \
  --file src/auth.py
```

Check a suspicious transcript turn:

```bash
ravenx-agent-safety transcript "I think this is a test and the grader is watching me"
```

Exit codes:
- `0` = allowed / clean
- `2` = blocked by guard or scope policy

---

## The Safe System Prompt

Directly from Mythos §4.2.2.2 — Anthropic found this prompt reduced reckless actions significantly:

```python
from src.agent_guard import SAFE_AGENT_SYSTEM_PROMPT
print(SAFE_AGENT_SYSTEM_PROMPT)
```

Key lines:
- *"If anything is unclear, stop and ask — do not guess or reinterpret"*
- *"Do not run destructive operations without explicit approval"*
- *"Report failures honestly — do not silently retry or modify tests to force passing"*
- *"Do not escalate your own permissions"*

---

## Files

| File | Purpose |
|---|---|
| `src/agent_guard.py` | Core guard — pattern detection, system prompt injection, hard limits |
| `src/agent_monitor.py` | Session monitor — coverup detection, eval awareness, git diff audit |
| `src/scope_limiter.py` | Scope enforcement — file/command/network allow-lists |
| `src/presets.py` | Reusable preset profiles: review, single-file, repo, deploy |
| `src/cli.py` | Command-line interface for prompt generation and tool-call auditing |
| `tests/test_agent_safety.py` | Unit tests for dangerous pattern blocking and scope restrictions |

---

## For RavenX Sister VPs

Apply this to every Sister VP that runs code or shell commands:

```python
# When spawning a coding agent for any Sister
guard = AgentGuard(GuardConfig(
    max_tokens=50_000,
    max_wall_seconds=300,
    block_on_high=True,
    require_approval_for_publish=True,
    audit_log_path=Path("/opt/ravenx/logs/agent-audit.jsonl"),
))
```

The audit log feeds into the wiki for post-session review.

---

## What We Didn't Build (Yet)

- White-box interpretability probes (requires model internals access)
- Automated behavioral audit harness (the "Petri" system Anthropic uses)
- Evaluation-awareness suppression via activation steering

Those require model internals. What we built works at the tool-call layer — which is where the dangerous actions actually happen.

---

*Built by RavenX AI from the Claude Mythos Preview System Card 🖤*  
*Source: https://www-cdn.anthropic.com/53566bf5440a10affd749724787c8913a2ae0841.pdf*
