This is a small Python wrapper I wrote to make Kerbrute-based password spraying a bit easier and safer. Instead of manually kicking off sprays and watching the clock, the script handles looping through a password list, running Kerbrute each time, and sleeping between batches of attempts so you don’t hammer a domain controller.

The script expects kerbrute to be installed and available in your $PATH (typically /usr/local/bin). If it can’t find it, it exits with a friendly reminder.

## Usage
```python
python3 sprayer.py \
  --users users.txt \
  --passwords passwords.txt \
  --domain example.com \
  --sleep 120 \
  --attempts 1
```

## How It Works

- You provide a list of usernames, a list of passwords, and the domain name.

- The script reads each password one-by-one.

- For each password, it calls:

```
kerbrute passwordspray -d <domain> <users_file> <password>
```

- You can also control:

  - How many attempts to make before the script takes a break (--attempts)

  - How long that break should be (--sleep in minutes)
