# Resume-safety review

## Scope and base

This change builds on [pull request 2](https://github.com/RedBready/kerbrute_repeater/pull/2), contributed by yaolin902, at exact head `405ea96dc144141393388feb5f3fe344857e9fb6`. The original contribution remains in the commit ancestry. The patch is against that PR head, not the repository's older `main` branch.

The review covered the wrapper's resume/cooldown logic, subprocess lifecycle, checkpoint and input consistency, output handling, and related failure paths. It did not expand concurrency, attack coverage, or credential-testing features.

## Findings addressed

1. **Cooldown bypass after interruption:** the PR deliberately wrote a past timestamp. Interrupted/failed rounds now preserve current timestamps after cleanup and are blocked from automatic replay. Clean resumes honor the remaining cooldown without rounding down; waits are monotonic within one invocation.
2. **Unsafe partial-user offsets:** concurrent stdout counts were sliced into the original username file, which could both skip and repeat accounts. Count-based user resume is disabled. Only completed whole-password checkpoints can resume.
3. **False completion on child failure:** `Popen` does not raise `CalledProcessError`; the original handler therefore failed to stop checkpoint advancement. The new code checks the actual exit status, terminal results, and final summary. Kerbrute's zero-exit early-return/fatal-error behavior is also handled conservatively.
4. **Crash/checkpoint inconsistency:** direct JSON overwrite could leave corrupt or stale resumable state. Intent is durably and atomically recorded before child launch. Failed writes halt progress, and an unfinished marker cannot automatically replay. A stable advisory lock prevents two processes using the same checkpoint concurrently.
5. **Input drift and repeated attempts:** modified/reordered lists could invalidate saved indices; duplicate user aliases could attempt one account repeatedly in a nominal round. User contents are pinned, password changes are append-only, duplicates are rejected, and each run uses a private username snapshot.
6. **Shutdown and cleanup:** terminate is followed by bounded wait, then kill/reap when needed. Ctrl-C, SIGTERM, and SIGHUP share cleanup; signal exceptions are deferred during process-handle capture and reaping. Temporary username files are cleaned on normal exception paths.
7. **Validation and sensitive output:** empty/corrupt/legacy checkpoints, invalid numbers, malformed/empty input lists, aliased paths, and invalid schemas fail safely. Password whitespace and leading dashes are preserved. Log/checkpoint permissions are private; password headings use indices, and important success/error diagnostics are saved before stopping.
8. **Documentation:** corrected the executable filename, documented zero-based indices, conservative recovery, platform/output compatibility, and remaining operating assumptions.

## Verification

On Python 3.12.14 (POSIX), the final code passed:

```sh
python3 -m unittest discover -s tests -v
# 46 tests passed; subprocesses, clock, sleeps and prompts mocked.
python3 -m py_compile password_spray.py tests/test_password_spray.py
git diff --check
```

The source snapshot had no existing test suite, linter configuration, or CI workflows. No live Kerberos request, authentication, or spraying was performed. Python 3.8+, macOS, and a real installed Kerbrute binary were not executed during this review.

The output protocol was checked against upstream Kerbrute commit `9cfb81e4fab8037acb44c678773ca3f93bc2b39c`:

- [Password-spray loop and completion summary](https://github.com/ropnop/kerbrute/blob/9cfb81e4fab8037acb44c678773ca3f93bc2b39c/cmd/passwordspray.go)
- [Worker counter, success/failure output, and cancellation](https://github.com/ropnop/kerbrute/blob/9cfb81e4fab8037acb44c678773ca3f93bc2b39c/cmd/worker.go)
- [Error classification](https://github.com/ropnop/kerbrute/blob/9cfb81e4fab8037acb44c678773ca3f93bc2b39c/session/errors.go)
- [Username normalization](https://github.com/ropnop/kerbrute/blob/9cfb81e4fab8037acb44c678773ca3f93bc2b39c/util/username.go)
- [Logger format](https://github.com/ropnop/kerbrute/blob/9cfb81e4fab8037acb44c678773ca3f93bc2b39c/util/log.go)

## Deliberate limitations and review decisions

- Partial or ambiguous rounds require manual reconciliation. This is an intentional safety tradeoff, not an exactly-once guarantee: a wrapper cannot know which network attempts completed before an abrupt stop.
- Original-format checkpoints cannot safely migrate automatically, even when `user_line` is zero.
- The implementation requires POSIX locking and a local filesystem that supports the needed atomic-write/durability operations. Windows is rejected explicitly.
- Independent session files, other tools, and other hosts do not share a target-account attempt budget. Use one coordinated authorized test plan.
- Trusted wall time is required across restarts; monotonic time covers waits only within a running process.
- SIGKILL and power/OS failure cannot run cleanup. A child may still be alive; `in_progress` prevents automatic resume, but process and audit reconciliation are manual.
- An unexpected Kerbrute output format fails closed. Compatibility with other versions needs separate review before use.
- Logs, terminal output, inputs, process arguments, and possibly Kerbrute-generated AS-REP files remain sensitive. Private wrapper log permissions do not hide OS process arguments or protect external backups.

## Applying the accompanying patch

Use a clean disposable checkout of the exact PR head and inspect the diff before applying it. Do not apply this patch directly to the older `main` tree or blindly over local work.

```sh
git rev-parse HEAD
# Must be: 405ea96dc144141393388feb5f3fe344857e9fb6
git status --short
# Must be empty before application.
git apply --check /path/to/kerbrute-repeater-resume-safety.patch
git apply /path/to/kerbrute-repeater-resume-safety.patch
python3 -m unittest discover -s tests -v
```

These review commands do not launch Kerbrute. Publication of a separate review branch does not merge or deploy the change.
