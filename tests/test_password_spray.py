"""Offline tests only: every child process and clock wait is mocked."""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import inspect
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import password_spray as spray


RESULTS = [f"[!] {user}@example.invalid:value - Invalid password\n" for user in ("alice", "bob", "carol")]
SUMMARY = "2026/10/16 12:00:00 >  Done! Tested 3 logins (0 successes) in 0.010 seconds\n"


class FakeClock:
    def __init__(self):
        self.now = datetime(2026, 10, 16, 12, 0, 0, 500000, tzinfo=timezone.utc)
        self.tick = 100.0
        self.sleeps = []
        self.on_sleep = None

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)
        self.tick += seconds

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.advance(seconds)
        if self.on_sleep:
            self.on_sleep()


class FakeOutput:
    def __init__(self, values):
        self.values = values
        self.closed = False

    def __iter__(self):
        for value in self.values:
            if isinstance(value, BaseException):
                raise value
            yield value

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, output=None, return_code=0, on_wait=None, timeout=False):
        self.stdout = FakeOutput(output if output is not None else RESULTS + [SUMMARY])
        self.return_code = return_code
        self.done = False
        self.terminated = False
        self.killed = False
        self.waited = []
        self.on_wait = on_wait
        self.timeout = timeout

    def poll(self):
        return self.return_code if self.done else None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waited.append(timeout)
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("mock", timeout)
        if self.on_wait:
            self.on_wait()
        self.done = True
        return self.return_code


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.users = self.directory / "users.txt"
        self.passwords = self.directory / "passwords.txt"
        self.session = self.directory / "session.json"
        self.log = self.directory / "success.log"
        self.users.write_text("alice\nbob\ncarol\n", encoding="utf-8")
        self.passwords.write_text("test-only-value\n", encoding="utf-8")
        self.args = ["--users", str(self.users), "--passwords", str(self.passwords),
                     "--domain", "example.invalid", "--sleep", "1", "--attempts", "10",
                     "--session-file", str(self.session), "--log-file", str(self.log)]
        self.clock = FakeClock()
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(redirect_stdout(self.output))
        self.stack.enter_context(redirect_stderr(self.errors))
        self.stack.enter_context(patch.object(spray.shutil, "which", return_value="/mock/kerbrute"))
        self.stack.enter_context(patch.object(spray.os, "access", return_value=True))
        self.popen = self.stack.enter_context(patch.object(spray.subprocess, "Popen"))
        self.popen.side_effect = lambda *args, **kwargs: FakeProcess()
        self.stack.enter_context(patch.object(spray, "utc_now", side_effect=lambda: self.clock.now))
        self.stack.enter_context(patch.object(spray.time, "monotonic", side_effect=lambda: self.clock.tick))
        self.stack.enter_context(patch.object(spray.time, "sleep", side_effect=self.clock.sleep))
        self.stack.enter_context(patch("builtins.input", return_value="y"))

    def checkpoint(self):
        return json.loads(self.session.read_text())

    def write_ready(self, index=0, elapsed=0):
        state = {
            "version": spray.SESSION_VERSION, "status": "ready", "users": str(self.users),
            "passwords": str(self.passwords), "log_file": str(self.log), "domain": "example.invalid",
            "domain_ip": "", "sleep": 1, "attempts": 10, "pwd_line": index, "user_line": 0,
            "users_hash": spray.digest(self.users.read_text()), "password_count": 1,
            "passwords_hash": spray.digest(["test-only-value"]),
            "last_sprayed": (self.clock.now - timedelta(seconds=elapsed)).isoformat(),
        }
        spray.save_session(self.session, state)
        return state

    def run_main(self, extra=()):
        return spray.main(self.args + list(extra))

    def test_success_requires_and_writes_durable_intent_before_launch(self):
        snapshots = []
        def launch(command, **kwargs):
            state = self.checkpoint()
            self.assertEqual((state["status"], state["pwd_line"], state["user_line"]), ("in_progress", 0, 0))
            self.assertEqual(spray.parse_time(state["last_sprayed"]), self.clock.now)
            snapshots.append(Path(command[-2]))
            self.assertEqual(snapshots[0].read_text(), self.users.read_text())
            self.assertTrue(kwargs["start_new_session"])
            self.assertEqual(command[-3], "--")
            return FakeProcess()
        self.popen.side_effect = launch
        self.assertEqual(self.run_main(), 0)
        state = self.checkpoint()
        self.assertEqual((state["status"], state["pwd_line"]), ("ready", 1))
        self.assertFalse(snapshots[0].exists())
        self.assertNotIn("test-only-value", self.log.read_text())
        self.assertEqual(self.session.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)

    def test_interrupt_out_of_order_output_never_becomes_user_offset(self):
        process = FakeProcess(["[!] carol@example.invalid - Invalid password\n", KeyboardInterrupt()],
                              on_wait=lambda: self.clock.advance(7))
        self.popen.side_effect = lambda *args, **kwargs: process
        before = self.clock.now
        self.assertEqual(self.run_main(), 130)
        state = self.checkpoint()
        self.assertEqual((state["status"], state["pwd_line"], state["user_line"]), ("interrupted", 0, 0))
        self.assertGreaterEqual(spray.parse_time(state["last_sprayed"]), before + timedelta(seconds=7))
        self.assertTrue(process.terminated)
        self.assertTrue(process.done)
        self.assertTrue(process.stdout.closed)
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.popen.call_count, 1)
        self.assertEqual(self.checkpoint(), state)

    def test_interrupt_before_first_output_is_not_a_clean_checkpoint(self):
        self.popen.side_effect = lambda *args, **kwargs: FakeProcess([KeyboardInterrupt()])
        self.assertEqual(self.run_main(), 130)
        self.assertEqual(self.checkpoint()["status"], "interrupted")
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.popen.call_count, 1)

    def test_timeout_after_terminate_escalates_to_kill_and_reaps(self):
        process = FakeProcess([KeyboardInterrupt()], timeout=True)
        self.popen.side_effect = lambda *args, **kwargs: process
        self.assertEqual(self.run_main(), 130)
        self.assertTrue(process.terminated and process.killed and process.done)
        self.assertEqual(process.waited, [5, None])

    def test_nonzero_exit_stops_without_advancing_or_next_password(self):
        self.passwords.write_text("first\nsecond\n")
        self.popen.side_effect = lambda *args, **kwargs: FakeProcess(return_code=2)
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.popen.call_count, 1)
        self.assertEqual((self.checkpoint()["status"], self.checkpoint()["pwd_line"]), ("failed", 0))

    def test_zero_exit_without_complete_summary_is_blocked(self):
        for output in ([], ["cannot open user file\n"],
                       [SUMMARY.replace("3 logins", "2 logins")],
                       [SUMMARY, "scanner error after summary\n"]):
            with self.subTest(output=output):
                self.session.unlink(missing_ok=True)
                self.popen.side_effect = lambda *args, **kwargs: FakeProcess(output)
                self.assertEqual(self.run_main(), 1)
                self.assertEqual(self.checkpoint()["pwd_line"], 0)
                self.assertEqual(self.checkpoint()["status"], "failed")

    def test_colored_complete_summary_is_accepted(self):
        self.popen.side_effect = lambda *args, **kwargs: FakeProcess(RESULTS + ["\x1b[32m" + SUMMARY.rstrip() + "\x1b[0m\n"])
        self.assertEqual(self.run_main(), 0)

    def test_spawn_error_preserves_failed_intent(self):
        self.popen.side_effect = OSError("mock spawn failure")
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.checkpoint()["status"], "failed")
        self.assertEqual(self.checkpoint()["pwd_line"], 0)
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.popen.call_count, 1)

    def test_stream_error_stops_child_before_checkpoint(self):
        process = FakeProcess([OSError("mock stream failure")])
        self.popen.side_effect = lambda *args, **kwargs: process
        self.assertEqual(self.run_main(), 1)
        self.assertTrue(process.terminated and process.done)
        self.assertEqual(self.checkpoint()["status"], "failed")

    def test_resume_waits_exact_fractional_remainder_before_launch(self):
        self.write_ready(elapsed=59.25)
        before = self.clock.now
        def launch(*args, **kwargs):
            self.assertGreaterEqual((self.clock.now - before).total_seconds(), 0.75)
            return FakeProcess()
        self.popen.side_effect = launch
        self.assertEqual(self.run_main(), 0)
        self.assertAlmostEqual(sum(self.clock.sleeps), 0.75)

    def test_completed_cooldown_does_not_add_delay(self):
        self.write_ready(elapsed=61)
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.clock.sleeps, [])

    def test_early_sleep_wakeup_does_not_shorten_cooldown(self):
        self.write_ready(elapsed=59)
        def early_sleep(seconds):
            self.clock.sleeps.append(seconds)
            self.clock.advance(min(seconds, 0.25))
        with patch.object(spray.time, "sleep", side_effect=early_sleep):
            self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(self.clock.sleeps), 4)
        self.assertEqual(self.clock.tick, 101)

    def test_interrupt_during_cooldown_preserves_ready_checkpoint(self):
        self.write_ready(elapsed=10)
        previous = self.session.read_bytes()
        with patch.object(spray.time, "sleep", side_effect=KeyboardInterrupt()):
            self.assertEqual(self.run_main(), 130)
        self.assertEqual(self.session.read_bytes(), previous)
        self.popen.assert_not_called()
        self.assertEqual(self.run_main(), 0)
        self.assertAlmostEqual(sum(self.clock.sleeps), 50)

    def test_crash_marker_is_never_automatically_retried(self):
        for status in ("in_progress", "interrupted", "failed"):
            with self.subTest(status=status):
                state = self.write_ready(elapsed=1000)
                state["status"] = status
                spray.save_session(self.session, state)
                self.assertEqual(self.run_main(), 1)
                self.assertEqual(self.checkpoint(), state)
        self.popen.assert_not_called()

    def test_legacy_session_even_zero_user_count_is_rejected(self):
        self.session.write_text(json.dumps({"pwd_line": 0, "user_line": 0, "last_sprayed": "2026-10-01 00:00:00"}))
        previous = self.session.read_bytes()
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.session.read_bytes(), previous)
        self.popen.assert_not_called()

    def test_empty_corrupt_and_wrong_type_session_are_not_overwritten(self):
        for content in ("", "{", "[]", "null"):
            with self.subTest(content=content):
                self.session.write_text(content)
                self.assertEqual(self.run_main(), 1)
                self.assertEqual(self.session.read_text(), content)
        self.popen.assert_not_called()

    def test_invalid_session_fields_are_rejected(self):
        for key, value in (("sleep", 0), ("attempts", -1), ("pwd_line", True),
                           ("pwd_line", 2), ("user_line", 1), ("user_line", False),
                           ("status", "unknown"), ("status", []), ("status", {}),
                           ("last_sprayed", "2026-10-16T00:00:00"), ("domain_ip", None)):
            with self.subTest(key=key, value=value):
                state = self.write_ready()
                state[key] = value
                self.session.write_text(json.dumps(state))
                self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()

    def test_partial_user_and_invalid_numeric_arguments_are_rejected(self):
        for args in (("--user-line", "1"), ("--user-line", "-1"), ("--pwd-line", "-1"),
                     ("--pwd-line", "2"), ("--sleep", "0"), ("--sleep", "-1"),
                     ("--attempts", "0"), ("--attempts", "-1")):
            with self.subTest(args=args):
                self.assertEqual(self.run_main(args), 1)
        self.popen.assert_not_called()

    def test_blank_inputs_are_rejected_before_launch(self):
        for users, passwords in (("", "one\n"), ("alice\n\nbob\n", "one\n"),
                                 ("alice\n", ""), ("alice\n", "one\n\ntwo\n")):
            self.users.write_text(users)
            self.passwords.write_text(passwords)
            self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()

    def test_changed_username_file_blocks_resume(self):
        self.write_ready()
        self.users.write_text("carol\nbob\nalice\n")
        self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()

    def test_changed_password_prefix_blocks_resume(self):
        self.write_ready()
        self.passwords.write_text("changed\ntest-only-value\n")
        self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()

    def test_append_only_password_change_is_allowed_without_skipping(self):
        self.write_ready(index=1, elapsed=61)
        self.passwords.write_text("test-only-value\nnext-value\n")
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.popen.call_count, 1)
        self.assertEqual(self.popen.call_args.args[0][-1], "next-value")
        self.assertEqual(self.checkpoint()["pwd_line"], 2)

    def test_reorder_during_wait_stops_before_next_round(self):
        self.passwords.write_text("one\ntwo\n")
        self.clock.on_sleep = lambda: self.passwords.write_text("two\none\n")
        self.assertEqual(self.run_main(("--attempts", "1")), 1)
        self.assertEqual(self.popen.call_count, 1)
        self.assertEqual(self.checkpoint()["pwd_line"], 1)

    def test_append_during_wait_is_observed(self):
        self.clock.on_sleep = lambda: self.passwords.write_text("test-only-value\nnext-value\n")
        self.assertEqual(self.run_main(("--attempts", "1")), 0)
        self.assertEqual(self.popen.call_count, 2)
        self.assertEqual([call.args[0][-1] for call in self.popen.call_args_list], ["test-only-value", "next-value"])

    def test_password_whitespace_and_leading_dash_are_preserved(self):
        self.passwords.write_text(" leading and trailing \n--not-an-option\n")
        self.assertEqual(self.run_main(), 0)
        self.assertEqual([call.args[0][-1] for call in self.popen.call_args_list], [" leading and trailing ", "--not-an-option"])
        self.assertTrue(all(call.args[0][-3] == "--" for call in self.popen.call_args_list))

    def test_atomic_replace_failure_keeps_previous_checkpoint_and_cleans_temp(self):
        previous = self.write_ready()
        with patch.object(spray.os, "replace", side_effect=OSError("mock disk failure")):
            with self.assertRaises(OSError):
                spray.save_session(self.session, dict(previous, status="in_progress"))
        self.assertEqual(self.checkpoint(), previous)
        self.assertEqual(list(self.directory.glob(".session-*")), [])

    def test_checkpoint_failure_before_launch_runs_no_process(self):
        with patch.object(spray, "save_session", side_effect=OSError("mock disk failure")):
            self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()

    def test_checkpoint_failure_after_launch_keeps_in_progress_marker(self):
        real_save = spray.save_session
        def save(path, state):
            if state["status"] == "ready":
                raise OSError("mock disk failure")
            return real_save(path, state)
        with patch.object(spray, "save_session", side_effect=save):
            self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.checkpoint()["status"], "in_progress")
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.popen.call_count, 1)

    def test_session_lock_blocks_overlapping_invocations(self):
        with spray.session_lock(self.session):
            self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()
        self.assertEqual(self.run_main(), 0)

    def test_aliasing_log_and_input_is_rejected_without_truncation(self):
        before = self.users.read_bytes()
        self.assertEqual(self.run_main(("--log-file", str(self.users))), 1)
        self.assertEqual(self.users.read_bytes(), before)
        self.popen.assert_not_called()

    def test_hardlinked_output_and_input_is_rejected(self):
        os.link(self.users, self.log)
        before = self.users.read_bytes()
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.users.read_bytes(), before)
        self.popen.assert_not_called()

    def test_log_open_failure_starts_no_process(self):
        self.log.mkdir()
        self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()

    def test_resume_uses_selected_checkpoint_not_embedded_path(self):
        state = self.write_ready(elapsed=61)
        other = self.directory / "unrelated.json"
        state["session_file"] = str(other)
        spray.save_session(self.session, state)
        self.assertEqual(self.run_main(), 0)
        self.assertFalse(other.exists())
        self.assertEqual(self.checkpoint()["pwd_line"], 1)

    def test_declining_resume_changes_nothing(self):
        self.write_ready()
        before = self.session.read_bytes()
        with patch("builtins.input", return_value="n"):
            self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.session.read_bytes(), before)
        self.popen.assert_not_called()

    def test_fatal_or_unknown_error_with_matching_summary_is_blocked(self):
        for error in ("NETWORK ERROR - Can't talk to KDC. Aborting...",
                      "KDC ERROR - Wrong Realm. Try adjusting the domain? Aborting...",
                      "USER LOCKED OUT", "Clock skew too great", "an unknown runtime failure"):
            with self.subTest(error=error):
                self.session.unlink(missing_ok=True)
                process = FakeProcess([f"[!] alice@example.invalid:value - {error}\n"] + RESULTS[1:] + [SUMMARY])
                self.popen.side_effect = lambda *args, **kwargs: process
                self.assertEqual(self.run_main(), 1)
                self.assertTrue(process.terminated and process.done)
                self.assertEqual((self.checkpoint()["status"], self.checkpoint()["pwd_line"]), ("failed", 0))
                self.assertIn(error, self.log.read_text())

    def test_complete_summary_without_terminal_results_is_blocked(self):
        self.popen.side_effect = lambda *args, **kwargs: FakeProcess([SUMMARY])
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.checkpoint()["pwd_line"], 0)

    def test_mixed_known_outcomes_complete_without_order_assumptions(self):
        self.popen.side_effect = lambda *args, **kwargs: FakeProcess([
            "2026/10/16 12:00:00 >  [!] carol@example.invalid:value - User does not exist\n",
            "2026/10/16 12:00:00 >  [+] VALID LOGIN:\t bob@example.invalid:value\n",
            "[!] alice@example.invalid:value - Got AS-REP (no pre-auth) but couldn't decrypt - bad password\n",
            SUMMARY,
        ])
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.checkpoint()["pwd_line"], 1)

    def test_login_error_does_not_advance(self):
        self.popen.side_effect = lambda *args, **kwargs: FakeProcess([
            "[+] VALID LOGIN WITH ERROR:\t alice@example.invalid:value\t (Clock skew is too great)\n"
        ] + RESULTS[1:] + [SUMMARY])
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.checkpoint()["pwd_line"], 0)
        self.assertIn("VALID LOGIN WITH ERROR", self.log.read_text())

    def test_duplicate_normalized_accounts_are_rejected_before_launch(self):
        for users in ("alice\nalice\n", "alice\nalice@example.invalid\n", "alice\nALICE\n"):
            with self.subTest(users=users):
                self.users.write_text(users)
                self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()

    def test_malformed_accounts_are_rejected_before_launch(self):
        for users in (" alice\n", "alice \n", "@example.invalid\n", "alice@@example.invalid\n"):
            with self.subTest(users=users):
                self.users.write_text(users)
                self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()

    def test_missing_checkpoint_time_is_rejected_without_traceback(self):
        state = self.write_ready()
        del state["last_sprayed"]
        self.session.write_text(json.dumps(state))
        self.assertEqual(self.run_main(), 1)
        self.popen.assert_not_called()

    def test_signal_handlers_are_restored_and_second_signal_is_deferred(self):
        handlers = {}
        previous = object()
        def install(signum, handler):
            handlers[signum] = handler
            return previous
        with patch.object(spray.signal, "signal", side_effect=install):
            with spray.termination_signals():
                handler = handlers[signal.SIGTERM]
                with self.assertRaises(spray.StopRequested) as context:
                    handler(signal.SIGTERM, None)
                self.assertEqual(context.exception.signum, signal.SIGTERM)
                handler(signal.SIGTERM, None)
        self.assertTrue(all(handler is previous for handler in handlers.values()))

    def test_termination_signal_reaps_child_and_blocks_partial_resume(self):
        for signum in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signum=signum):
                self.session.unlink(missing_ok=True)
                process = FakeProcess([spray.StopRequested(signum)])
                self.popen.side_effect = lambda *args, **kwargs: process
                self.assertEqual(self.run_main(), 128 + signum)
                self.assertTrue(process.terminated and process.done)
                self.assertEqual(self.checkpoint()["status"], "interrupted")

    def test_signal_during_spawn_is_deferred_until_child_handle_is_captured(self):
        process = FakeProcess()
        def launch(*args, **kwargs):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return process
        self.popen.side_effect = launch
        self.assertEqual(self.run_main(), 128 + signal.SIGTERM)
        self.assertTrue(process.terminated and process.done and process.stdout.closed)
        self.assertEqual(self.checkpoint()["status"], "interrupted")

    def test_signal_during_cleanup_cannot_interrupt_reaping(self):
        process = FakeProcess([OSError("mock output error")],
                              on_wait=lambda: signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None))
        self.popen.side_effect = lambda *args, **kwargs: process
        self.assertEqual(self.run_main(), 128 + signal.SIGTERM)
        self.assertTrue(process.terminated and process.done and process.stdout.closed)
        self.assertEqual(self.checkpoint()["status"], "interrupted")

    def test_signal_at_cleanup_entry_is_deferred_and_child_is_reaped(self):
        source, first_line = inspect.getsourcelines(spray.run_round)
        target = first_line + next(index for index, line in enumerate(source)
                                   if line.strip() == "if process is not None:")
        process = FakeProcess([OSError("mock output error")])
        self.popen.side_effect = lambda *args, **kwargs: process
        triggered = False
        def trace(frame, event, arg):
            nonlocal triggered
            if (not triggered and event == "line" and frame.f_code is spray.run_round.__code__
                    and frame.f_lineno == target):
                triggered = True
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return trace
        previous_trace = sys.gettrace()
        try:
            sys.settrace(trace)
            result = self.run_main()
        finally:
            sys.settrace(previous_trace)
        self.assertTrue(triggered)
        self.assertEqual(result, 128 + signal.SIGTERM)
        self.assertTrue(process.terminated and process.done and process.stdout.closed)
        self.assertEqual(self.checkpoint()["status"], "interrupted")


if __name__ == "__main__":
    unittest.main()
