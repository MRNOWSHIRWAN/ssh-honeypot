"""Build an offline HTML report from local lab events. No network requests."""
import argparse
from collections import Counter
import html
import json
import os
from pathlib import Path

MAX_LOG_BYTES = 5_000_000
MAX_ROWS = 20_000


def read_events(path):
    if path.stat().st_size > MAX_LOG_BYTES:
        raise ValueError('log exceeds 5 MB; rotate it before reporting')
    records, skipped = [], 0
    with path.open(encoding='utf-8') as stream:
        for index, line in enumerate(stream):
            if index >= MAX_ROWS:
                raise ValueError('log exceeds 20,000 lines; rotate it before reporting')
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


def render_report(records, skipped=0):
    counts = Counter(row['event'] for row in records)
    ips = Counter(row['client_ip'] for row in records if row['event'] == 'connection')
    commands = Counter(row['command_name'] for row in records if row['event'] == 'command')
    esc = lambda value: html.escape(str(value), quote=True)
    def table(counter, heading):
        rows = ''.join(f'<tr><td>{esc(name)}</td><td>{count}</td></tr>' for name, count in counter.most_common(20))
        return f'<section><h2>{heading}</h2><table><thead><tr><th>Name</th><th>Count</th></tr></thead><tbody>{rows or "<tr><td colspan=2>No events</td></tr>"}</tbody></table></section>'
    timeline = ''.join('<tr>' + ''.join(f'<td>{esc(row[key])}</td>' for key in
                        ('timestamp_utc', 'event', 'client_ip', 'username', 'command_name')) + '</tr>'
                       for row in records[-100:][::-1])
    return '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SSH Honeypot Lab | Local report</title><style>
body{margin:0;background:#101827;color:#e5edf7;font:16px system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:32px 20px}h1{font-size:32px;margin-bottom:8px}p{color:#b7c5da;line-height:1.6}.cards,.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}.card,section{background:#19263b;border:1px solid #304562;border-radius:12px;padding:20px}.card strong{display:block;font-size:28px;color:#7dd3fc}.card span{color:#c0cee0}h2{font-size:20px}table{border-collapse:collapse;width:100%;font-size:14px}td,th{text-align:left;padding:10px 6px;border-bottom:1px solid #304562;overflow-wrap:anywhere}th{color:#7dd3fc}.grid{margin:20px 0}.scroll{overflow-x:auto}footer{color:#b7c5da;font-size:14px;margin-top:24px}.timeline{min-width:700px}</style>
<main><h1>SSH Honeypot Lab</h1><p>Local defensive telemetry. Simulated commands only. IP addresses do not prove malicious intent or attribution.</p><div class="cards">''' + ''.join(
        f'<div class="card"><strong>{value}</strong><span>{label}</span></div>' for label, value in
        [('Connections', counts['connection']), ('Password attempts (redacted)', counts['password_auth']),
         ('Commands observed', counts['command']), ('Skipped malformed lines', skipped)]) + '</div><div class="grid">' + table(ips, 'Connection sources') + table(commands, 'Command names') + '''</div><section><h2>Latest events (up to 100)</h2><div class="scroll"><table class="timeline"><thead><tr><th>UTC time</th><th>Event</th><th>Client IP</th><th>Username</th><th>Command name</th></tr></thead><tbody>''' + (timeline or '<tr><td colspan=5>No events yet. Run a local test session first.</td></tr>') + '''</tbody></table></div></section><footer>Private local report. Passwords and command arguments are excluded. No external scripts, fonts or tracking.</footer></main></html>'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, default=Path('events.jsonl'))
    parser.add_argument('--output', type=Path, default=Path('report.html'))
    args = parser.parse_args(argv)
    try:
        records, skipped = read_events(args.log)
        # Do not overwrite the input log with report HTML.
        if args.output.resolve() == args.log.resolve():
            raise ValueError('output must differ from input log')
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            output.write(render_report(records, skipped))
    except (OSError, ValueError) as exc:
        parser.exit(2, f'Cannot build report: {exc}\n')
    print(f'Report saved to {args.output}; {len(records)} events, {skipped} malformed lines skipped. Keep it private.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
