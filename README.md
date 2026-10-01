# SSH Honeypot Lab

A local-first Python SSH honeypot for learning defensive telemetry. It accepts simulated password logins into a fake shell, records the client IP and username, and records command names without running commands on the host. Attempted passwords and command arguments are not stored.

## Run locally

Requires Python 3.10 or newer.

```sh
git clone https://github.com/MRNOWSHIRWAN/ssh-honeypot.git
cd ssh-honeypot
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python honeypot.py
```

In another terminal, connect with a disposable username and any dummy password:

```sh
ssh -p 2222 demo@127.0.0.1
```

The default bind address is 127.0.0.1. The server generates its own local host key on first run. Try `help`, `whoami`, `pwd`, `ls`, and `exit`. These responses are simulated. Other commands return a simulated "command not found" response; nothing is executed, downloaded or forwarded. Ctrl+C stops the server.

On Windows, activate the environment with `.venv\Scripts\Activate.ps1` instead of the `source` command.

## Telemetry and limits

Events are appended to `events.jsonl`: UTC timestamp, session ID, client IP, event type and bounded metadata. Password attempts record only the fact that password authentication was attempted. Command events retain only the first command word and argument count; arguments are discarded. Usernames and command names are limited and control characters removed. Do not enter real secrets into the fake shell.

New event logs and generated host keys use owner-only permissions on POSIX systems. Existing file permissions are not changed. Logs are sensitive research data; keep them private, limit retention and do not commit them. Private keys and logs are ignored by Git.

This is a small learning lab, not a production honeypot or proof of malicious activity. Client IPs alone do not establish attribution. Sessions run one at a time with time, command and input-size limits. Forwarding, SFTP and host command execution are not supported. The server refuses non-loopback binding in this version. Do not expose it through tunnels or port forwarding. Any future internet deployment needs separate approval, isolation and a privacy/retention plan.

## Local report

After a test session, stop the server and build an offline dashboard:

```sh
python report.py --log events.jsonl --output report.html
```

Open `report.html` in your browser. It shows connection counts, redacted password-attempt counts, command names, source IP counts and the latest 100 events. It uses no external scripts or tracking, escapes event text, and excludes passwords and command arguments even if an imported log contains them. The report is private local data, not a public site. It accepts logs up to 5 MB and 20,000 lines; rotate logs before reaching those limits. Malformed lines are counted and skipped.

## Tests

```sh
python -m unittest discover -s tests -v
```

Tests cover log redaction, fake-shell behavior, safety limits and a loopback SSH connection. They do not demonstrate production hardening or internet attack observations.

## Next steps

Improve the fake-shell simulation, log rotation and test coverage. No real attacker data or public deployment is included.
