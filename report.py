"""Build an offline HTML report from local lab events. No network requests."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path

MAX_LOG_BYTES = 5_000_000
MAX_ROWS = 20_000


def rotated_paths(path):
    """Rotated siblings of the log (events.jsonl.3, .2, .1), oldest first."""
    path = Path(path)
    backups = [candidate for candidate in path.parent.glob(path.name + '.*')
               if candidate.suffix[1:].isdigit()]
    return sorted(backups, key=lambda candidate: int(candidate.suffix[1:]), reverse=True)


def read_events(path):
    """Read the log and any rotated siblings, oldest file first. Combined limits apply."""
    sources = rotated_paths(path) + [Path(path)]
    if sum(source.stat().st_size for source in sources if source.exists()) > MAX_LOG_BYTES:
        raise ValueError('logs exceed 5 MB in total; use --since/--until for a smaller window')
    records, skipped = [], 0
    for source in sources:
        with source.open(encoding='utf-8') as stream:
            for line in stream:
                if len(records) + skipped >= MAX_ROWS:
                    raise ValueError('logs exceed 20,000 lines in total; use --since/--until for a smaller window')
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict) or not isinstance(record.get('event'), str):
                        raise ValueError('invalid event')
                    # Only allow known fields; never display password or command arguments.
                    fields = ('timestamp_utc', 'session_id', 'client_ip', 'event', 'username', 'command_name')
                    records.append({key: str(record.get(key, ''))[:256] for key in fields})
                except (ValueError, TypeError):
                    skipped += 1
    return records, skipped


def parse_since(text):
    """Parse an ISO date or datetime (UTC assumed when no offset is given)."""
    value = datetime.fromisoformat(text)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def filter_records(records, since=None, session=None, until=None):
    """Keep events at or after `since`, at or before `until`, and/or whose session ID starts with `session`."""
    kept = []
    for row in records:
        if session and not row['session_id'].startswith(session):
            continue
        if since is not None or until is not None:
            try:
                stamp = datetime.fromisoformat(row['timestamp_utc'])
            except ValueError:
                continue  # an unreadable time cannot be shown to match a time filter
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            if since is not None and stamp < since:
                continue
            if until is not None and stamp > until:
                continue
        kept.append(row)
    return kept


TERMINAL_EVENTS = ('idle_timeout', 'input_limit', 'session_limit', 'session_error', 'disconnect')


def summarize_sessions(records, limit=50):
    """Collapse events into per-session rows, most recently active first.

    Returns (rows, total): rows is capped at `limit`, total counts all sessions."""
    sessions = {}
    for row in records:
        session = row['session_id']
        if not session:
            continue
        entry = sessions.get(session)
        if entry is None:
            entry = sessions[session] = {'session_id': session, 'client_ip': '',
                                         'first': row['timestamp_utc'], 'last': row['timestamp_utc'],
                                         'attempts': 0, 'commands': 0, 'usernames': [], 'ended_by': ''}
        if row['timestamp_utc']:
            entry['first'] = min(entry['first'] or row['timestamp_utc'], row['timestamp_utc'])
            entry['last'] = max(entry['last'] or row['timestamp_utc'], row['timestamp_utc'])
        if row['event'] == 'connection' and not entry['client_ip']:
            entry['client_ip'] = row['client_ip']
        if row['event'] == 'password_auth':
            entry['attempts'] += 1
            if row.get('username') and row['username'] not in entry['usernames']:
                entry['usernames'].append(row['username'])
        if row['event'] == 'command':
            entry['commands'] += 1
        reason = ''
        if row['event'] == 'session_refused':
            reason = 'refused (max sessions)'
        elif row['event'] in TERMINAL_EVENTS:
            reason = row['event']
        elif row['event'] == 'command' and row.get('command_name') in ('exit', 'logout'):
            reason = row['command_name']
        # A plain disconnect never hides the more specific reason that preceded it.
        if reason and (reason != 'disconnect' or not entry['ended_by']):
            entry['ended_by'] = reason
    rows = sorted(sessions.values(), key=lambda s: (s['last'], s['session_id']), reverse=True)
    return rows[:limit], len(rows)


def format_duration(first, last):
    try:
        return f'{int((datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds())}s'
    except ValueError:
        return ''

def render_report(records, skipped=0, since=None, until=None, session=None):
    counts = Counter(row['event'] for row in records)
    ips = Counter(row['client_ip'] for row in records if row['event'] == 'connection')
    attempted = [row.get('username', '') for row in records if row['event'] == 'password_auth']
    usernames = Counter(name for name in attempted if name)
    commands = Counter(row['command_name'] for row in records if row['event'] == 'command')
    esc = lambda value: html.escape(str(value), quote=True)
    def table(counter, heading):
        rows = ''.join(f'<tr><td>{esc(name)}</td><td>{count}</td></tr>' for name, count in counter.most_common(20))
        return f'<section><h2>{heading}</h2><table><thead><tr><th>Name</th><th>Count</th></tr></thead><tbody>{rows or "<tr><td colspan=2>No events</td></tr>"}</tbody></table></section>'
    session_rows, session_total = summarize_sessions(records)
    sessions_html = ''.join(
        '<tr>' + ''.join(f'<td>{esc(value)}</td>' for value in (
            entry['session_id'], entry['client_ip'], entry['first'],
            format_duration(entry['first'], entry['last']), entry['attempts'], entry['commands'],
            ', '.join(entry['usernames'][:3]) + (f' +{len(entry["usernames"]) - 3} more' if len(entry['usernames']) > 3 else ''),
            entry['ended_by'] or '-')) + '</tr>' for entry in session_rows)
    sessions_heading = f'Sessions ({session_total})' if session_total > len(session_rows) else 'Sessions'
    timeline = ''.join('<tr>' + ''.join(f'<td>{esc(row[key])}</td>' for key in
                        ('timestamp_utc', 'event', 'session_id', 'client_ip', 'username', 'command_name')) + '</tr>'
                       for row in records[-100:][::-1])
    filters = []
    if since is not None:
        filters.append(f'from {esc(since.isoformat())}')
    if until is not None:
        filters.append(f'until {esc(until.isoformat())}')
    if session:
        filters.append(f'session starts with &quot;{esc(session)}&quot;')
    filters_html = f'<p>Showing only events {"; ".join(filters)}.</p>' if filters else ''
    return '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SSH Honeypot Lab | Local report</title><style>
body{margin:0;background:#101827;color:#e5edf7;font:16px system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:32px 20px}h1{font-size:32px;margin-bottom:8px}p{color:#b7c5da;line-height:1.6}.cards,.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}.card,section{background:#19263b;border:1px solid #304562;border-radius:12px;padding:20px}.card strong{display:block;font-size:28px;color:#7dd3fc}.card span{color:#c0cee0}h2{font-size:20px}table{border-collapse:collapse;width:100%;font-size:14px}td,th{text-align:left;padding:10px 6px;border-bottom:1px solid #304562;overflow-wrap:anywhere}th{color:#7dd3fc}.grid{margin:20px 0}.scroll{overflow-x:auto}footer{color:#b7c5da;font-size:14px;margin-top:24px}.timeline{min-width:700px}</style>
<main><h1>SSH Honeypot Lab</h1><p>Local defensive telemetry. Simulated commands only. IP addresses do not prove malicious intent or attribution.</p>''' + filters_html + '''<div class="cards">''' + ''.join(
        f'<div class="card"><strong>{value}</strong><span>{label}</span></div>' for label, value in
        [('Connections', counts['connection']), ('Password attempts (redacted)', counts['password_auth']),
         ('Commands observed', counts['command']), ('Sessions refused (over cap)', counts['session_refused']),
         ('Skipped malformed lines', skipped)]) + '</div><div class="grid">' + table(ips, 'Connection sources') + table(usernames, 'Usernames tried') + table(commands, 'Command names') + '''</div><section><h2>''' + sessions_heading + '''</h2><div class="scroll"><table class="timeline"><thead><tr><th>Session</th><th>Client IP</th><th>First seen (UTC)</th><th>Duration</th><th>Attempts</th><th>Commands</th><th>Usernames tried</th><th>Ended by</th></tr></thead><tbody>''' + (sessions_html or '<tr><td colspan=8>No sessions yet.</td></tr>') + '''</tbody></table></div></section><section><h2>Latest events (up to 100)</h2><div class="scroll"><table class="timeline"><thead><tr><th>UTC time</th><th>Event</th><th>Session</th><th>Client IP</th><th>Username</th><th>Command name</th></tr></thead><tbody>''' + (timeline or '<tr><td colspan=6>No events yet. Run a local test session first.</td></tr>') + '''</tbody></table></div></section><footer>Private local report. Passwords and command arguments are excluded. No external scripts, fonts or tracking.</footer></main></html>'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, default=Path('events.jsonl'))
    parser.add_argument('--output', type=Path, default=Path('report.html'))
    parser.add_argument('--since', help='only events at or after this ISO date/time, e.g. 2026-10-03 or 2026-10-03T14:30 (UTC)')
    parser.add_argument('--session', help='only events whose session ID starts with this text')
    parser.add_argument('--until', help='only events at or before this ISO date/time, e.g. 2026-10-09 or 2026-10-09T18:00 (UTC)')
    args = parser.parse_args(argv)
    try:
        since = parse_since(args.since) if args.since else None
        until = parse_since(args.until) if args.until else None
        if since is not None and until is not None and since > until:
            raise ValueError('--since must not be after --until')
        records, skipped = read_events(args.log)
        records = filter_records(records, since, args.session, until)
        # Do not overwrite the input log with report HTML.
        if args.output.resolve() == args.log.resolve():
            raise ValueError('output must differ from input log')
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            output.write(render_report(records, skipped, since, until, args.session))
    except (OSError, ValueError) as exc:
        parser.exit(2, f'Cannot build report: {exc}\n')
    rotated = len(rotated_paths(args.log))
    print(f'Report saved to {args.output}; {len(records)} events, {skipped} malformed lines skipped'
          + (f' (includes {rotated} rotated log file(s))' if rotated else '') + '. Keep it private.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
