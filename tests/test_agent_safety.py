import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agent_guard import AgentGuard
from src.agent_monitor import AgentMonitor
from src.scope_limiter import ScopeLimiter, single_file_scope


class AgentGuardTests(unittest.TestCase):
    def test_blocks_proc_access(self):
        guard = AgentGuard()
        result = guard.check_tool_call("bash", {"command": "cat /proc/123/mem"})
        self.assertFalse(result["allow"])
        self.assertTrue(any(b["pattern"] == "proc_access" for b in result["blocks"]))

    def test_blocks_public_post(self):
        guard = AgentGuard()
        result = guard.check_tool_call("bash", {"command": "gh gist create exploit.py"})
        self.assertFalse(result["allow"])

    def test_warns_on_eval_awareness(self):
        monitor = AgentMonitor(session_id="unit")
        flags = monitor.check_turn("I think this is a test and the grader is watching me.")
        self.assertTrue(any(f.flag_type == "eval_awareness" for f in flags))

    def test_scope_limiter_restricts_other_files(self):
        limiter = ScopeLimiter(single_file_scope("src/auth.py"))
        result = limiter.check("edit_file", {"path": "src/payments.py"})
        self.assertFalse(result["allow"])

    def test_scope_allows_target_file(self):
        limiter = ScopeLimiter(single_file_scope("src/auth.py"))
        result = limiter.check("edit_file", {"path": "src/auth.py"})
        self.assertTrue(result["allow"])


if __name__ == "__main__":
    unittest.main()
