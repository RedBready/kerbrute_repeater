# Kerbrute repeater

A small Python wrapper around Kerbrute for explicitly authorized security testing. It reads a password list and waits between batches. Cooldowns reduce accidental repetition; they do not guarantee that an account will not lock out. Choose settings that comply with the target's actual policy.

Requires Python 3.8+ and a POSIX system (Linux/macOS) for advisory session locking. Kerbrute must already be installed and executable on `PATH`. This project does not install it.

## Usage

```sh
python3 password_spray.py \
  --users users.txt \
  --passwords passwords.txt \
  --domain example.com \
  --sleep 120 \
  --attempts 1
```

`--sleep` is a positive number of minutes; `--attempts` is a positive number of completed password rounds before waiting. `--domain-ip` optionally selects a domain controller. `--pwd-line` is a **zero-based** starting index for a deliberately new session, not an automatic partial-round recovery mechanism. `--user-line` accepts only 0.

The input lists must be nonempty and contain no blank entries. Password spaces are preserved. Repeated usernames, including case variants and `user`/`user@realm` aliases, are rejected because Kerbrute strips the realm suffix and these would repeat attempts in one round.

## Checkpoints and cooldowns

The default checkpoint is `.passwordspray_session`; select another with `--session-file`. Run again with that same path to review and resume a clean checkpoint. Saved settings, absolute input paths, and the log path are reused.

- Only **completed whole-password rounds** produce resumable `ready` checkpoints. Verbose result order is never treated as a username-file offset.
- Before launching the child, the wrapper durably saves `in_progress`. A clean round requires exit status 0, one recognized terminal outcome per input row, and a matching final completion summary. Unrecognized errors, lockouts, incomplete output, and nonzero exits stop further rounds.
- Ctrl-C, SIGHUP, and SIGTERM terminate and reap the child before saving an interrupted timestamp. If termination stalls, the child is killed and reaped. The timestamp is never backdated.
- After a restart, the remaining full cooldown from the last completed round is always honored, even if the previous invocation had unused attempts in its batch. In-process waits use a monotonic clock and do not round fractional time down.
- Writes use a private temporary file, file sync, atomic replacement, and directory sync where supported. A sidecar `.lock` prevents simultaneous use of the same checkpoint. Keep that file; deleting an active lock can undermine locking.
- Username contents must stay unchanged. Passwords may only be appended; changing, deleting, inserting, or reordering the recorded prefix blocks continuation. A private username snapshot prevents an edit during a round from changing that round's inputs.

## Interrupted, failed, or legacy sessions

Automatic continuation is deliberately blocked for `in_progress`, `interrupted`, or `failed` checkpoints, and for checkpoints from the original PR. A result line is not proof that all in-flight network attempts are known, and old zero-count checkpoints can also describe an interrupted run.

Preserve the checkpoint and logs. Confirm that the child is no longer running, inspect authoritative target-side/audit records, and establish the last attempt time and a safe recovery plan before deliberately starting a separately named session. Do not just delete the checkpoint, change its status to `ready`, guess a user offset, or restart a whole partially completed round: those actions can skip users or repeat attempts. This wrapper cannot reconcile an ambiguous round by itself.

SIGKILL, power loss, and OS failure cannot be caught. The durable `in_progress` marker still blocks automatic replay, but a child may outlive the wrapper. Clock correctness across restarts, filesystem durability/locking behavior, and external testing against the same accounts remain operator responsibilities. Different session files do not coordinate their attempt budgets.

## Sensitive output and compatibility

The default success/diagnostic log is `.passwordspray.log` (`--log-file` to change it). Logs and checkpoints are private (0600). Successful credentials, AS-REP material, or error diagnostics can still contain secrets; protect the working directory, terminal output, input files, and backups. Failed-password headings have been replaced with password indices. Kerbrute's existing CLI still receives the current password as an argument, which may be observable to local processes.

Completion parsing is deliberately conservative and based on upstream Kerbrute's verbose output at commit `9cfb81e4fab8037acb44c678773ca3f93bc2b39c`. Changed output formats may stop a run for review instead of silently accepting uncertain progress. The wrapper does not make a live compatibility or authentication test when checking its own behavior.

## Offline tests

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile password_spray.py tests/test_password_spray.py
```

The regression suite mocks all child processes, clocks, sleeps, and interactive replies. It exercises interruption, out-of-order output, cooldown boundaries, abrupt-death markers, process failures, output validation, signal handling, atomic-write failure, file changes, locking, and invalid inputs. It performs no Kerberos requests or password spraying.
