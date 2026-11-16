"""Generate synthetic demo events so a fresh clone can build a report without live sessions.

All data is fictional: session IDs are zero-padded counters, client IPs come from the
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and no password
or command argument ever appears - the same fields the real log's report allowlist keeps.
Run: python3 samples/make_demo_events.py > demo_events.jsonl
"""
from datetime import datetime, timedelta, timezone
import json
import sys

start = datetime(2026, 10, 20, 1, 0, tzinfo=timezone.utc)
clock = [0]  # mutable so add() can advance a shared timeline


def add(event, session, client_ip, **fields):
    clock[0] += 7
    record = {'timestamp_utc': (start + timedelta(seconds=clock[0])).isoformat(),
              'event': event, 'session_id': session, 'client_ip': client_ip}
    record.update(fields)
    print(json.dumps(record, ensure_ascii=True))


def session(number, client_ip, usernames, commands, ending):
    sid = f'{number:032x}'
    add('connection', sid, client_ip)
    for name in usernames:
        add('password_auth', sid, client_ip, username=name, password='[REDACTED]')
    for command in commands:
        name, _, rest = command.partition(' ')
        add('command', sid, client_ip, command_name=name, argument_count=1 if rest else 0)
    if ending:
        add(ending, sid, client_ip)
    add('disconnect', sid, client_ip)


# A curious visitor who pokes around and leaves cleanly.
session(1, '192.0.2.10', ['root'], ['whoami', 'pwd', 'ls', 'cat notes.txt', 'exit'], None)
# Several password guesses, a longer look around, then idle.
session(2, '203.0.113.7', ['root', 'admin', 'ubuntu'], ['uname', 'uptime', 'help'], 'idle_timeout')
# A quick look from a second address at the same source network.
session(3, '198.51.100.23', ['demo'], ['ls', 'whoami', 'exit'], None)
# An over-cap caller is refused before any login (the lab serves at most 8 at once).
add('session_refused', f'{4:032x}', '203.0.113.7', reason='max_sessions_reached')
# A visitor who only runs one non-interactive command.
session(5, '192.0.2.44', ['test'], ['hostname'], 'session_limit')
