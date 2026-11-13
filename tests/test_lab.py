import io
import json
import logging
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import timezone

import paramiko
import honeypot
import report


class LabTests(unittest.TestCase):
    def test_shell_never_executes_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'owned'
            name, args, response, stop = honeypot.FakeShell('demo').respond(f'touch {marker}')
            self.assertFalse(marker.exists())
            self.assertEqual((name, args, stop), ('touch', 1, False))
            self.assertIn('simulated', response)

    def test_fixed_shell_responses(self):
        shell = honeypot.FakeShell('demo')
        self.assertEqual(shell.respond('whoami')[2], 'demo\r\n')
        self.assertEqual(shell.respond('pwd')[2], '/home/demo\r\n')
        self.assertTrue(shell.respond('exit')[3])

    def test_extended_shell_commands_are_simulated(self):
        shell = honeypot.FakeShell('demo')
        self.assertEqual(shell.respond('id')[2], 'uid=1000(demo) gid=1000(demo) groups=1000(demo)\r\n')
        self.assertEqual(honeypot.FakeShell('admin').respond('id')[2].count('admin'), 3)  # tracks the session name
        self.assertEqual(shell.respond('hostname')[2], 'lab-vm\r\n')
        self.assertIn('(simulated)', shell.respond('uptime')[2])
        help_text = shell.respond('help')[2]
        for name in ('whoami', 'id', 'hostname', 'uptime', 'exit'):
            self.assertIn(name, help_text)

    def test_fake_shell_cat_matches_the_ls_listing(self):
        shell = honeypot.FakeShell('demo')
        content = shell.respond('cat notes.txt')[2]
        self.assertIn('simulation', content)
        self.assertNotIn('command not found', content)  # ls lists notes.txt, so cat must find it
        self.assertIn('No such file or directory (simulated)', shell.respond('cat secret.txt')[2])
        self.assertIn('missing file operand (simulated)', shell.respond('cat')[2])
        self.assertIn('cat', shell.respond('help')[2])

    def test_password_redacted_and_forwarding_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            server = honeypot.LabServer(honeypot.EventLog(path), 'test', '127.0.0.1')
            self.assertEqual(server.check_auth_password('user\x00name', 'PRIVATE_SECRET'), paramiko.AUTH_SUCCESSFUL)
            server.flush()
            text = path.read_text()
            self.assertNotIn('PRIVATE_SECRET', text)
            self.assertIn('[REDACTED]', text)
            self.assertEqual(json.loads(text)['username'], 'username')
            self.assertNotEqual(server.check_channel_request('direct-tcpip', 0), paramiko.OPEN_SUCCEEDED)
            self.assertEqual(server.check_channel_request('session', 1), paramiko.OPEN_SUCCEEDED)
            self.assertNotEqual(server.check_channel_request('session', 2), paramiko.OPEN_SUCCEEDED)
            self.assertFalse(server.check_channel_subsystem_request(None, 'sftp'))

    def test_nonloopback_and_invalid_port_rejected(self):
        for options in (['--host', '0.0.0.0'], ['--host', 'example.com'], ['--port', '0']):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
                honeypot.main(options)
            self.assertEqual(ctx.exception.code, 2)

    def test_control_characters_and_size_are_bounded(self):
        self.assertEqual(honeypot.bounded('\x1b\nabc'), 'abc')
        self.assertEqual(len(honeypot.bounded('a' * 500)), 128)

    def test_exec_size_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            server = honeypot.LabServer(honeypot.EventLog(Path(folder)/'e'), 's', '127.0.0.1')
            self.assertFalse(server.check_channel_exec_request(None, b'a' * 1025))
            self.assertIsNone(server.exec_command)

    def test_report_escapes_html_and_excludes_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            path.write_text(json.dumps(dict(event='command', client_ip='127.0.0.1',
                username='<script>alert(1)</script>', command_name='ls', password='SECRET',
                arguments='PRIVATE')) + '\nnot-json\n')
            records, skipped = report.read_events(path)
            output = report.render_report(records, skipped)
            self.assertEqual(skipped, 1)
            self.assertNotIn('<script>', output)
            self.assertNotIn('SECRET', output)
            self.assertNotIn('PRIVATE', output)
            self.assertIn('&lt;script&gt;', output)

    def test_report_timeline_shows_session_ids_for_filtering(self):
        records = [{'timestamp_utc': '2026-10-20T01:00:00+00:00', 'event': 'command',
                    'session_id': 'abc123session', 'client_ip': '127.0.0.1',
                    'username': 'demo', 'command_name': 'ls'}]
        output = report.render_report(records, 0)
        self.assertIn('<th>Session</th>', output)
        self.assertIn('abc123session', output)  # the --session filter value is copyable from the report

    def test_report_counts_attempted_usernames(self):
        base = {'timestamp_utc': '2026-10-28T00:00:00+00:00', 'session_id': 's1',
                'client_ip': '127.0.0.1', 'command_name': ''}
        records = [dict(base, event='password_auth', username='admin'),
                   dict(base, event='password_auth', username='admin'),
                   dict(base, event='password_auth', username='root'),
                   dict(base, event='password_auth', username=''),       # nothing to list
                   dict(base, event='password_auth', username='<i>x</i>'),
                   dict(base, event='connection', username='demo')]       # only auth attempts count
        output = report.render_report(records, 0)
        section = output.split('Usernames tried', 1)[1].split('</section>', 1)[0]
        self.assertIn('<td>admin</td><td>2</td>', section)
        self.assertIn('<td>root</td><td>1</td>', section)
        self.assertNotIn('<td></td>', section)
        self.assertNotIn('<td>demo</td>', section)      # a connection username is not an attempt
        self.assertNotIn('<i>x</i>', output)
        self.assertIn('&lt;i&gt;x&lt;/i&gt;', section)

    def test_report_summarizes_sessions(self):
        records = [
            {'timestamp_utc': '2026-10-20T01:00:00+00:00', 'event': 'connection', 'session_id': 'sess-a', 'client_ip': '127.0.0.1', 'username': '', 'command_name': ''},
            {'timestamp_utc': '2026-10-20T01:00:10+00:00', 'event': 'password_auth', 'session_id': 'sess-a', 'client_ip': '127.0.0.1', 'username': '<b>root</b>', 'command_name': ''},
            {'timestamp_utc': '2026-10-20T01:01:00+00:00', 'event': 'command', 'session_id': 'sess-a', 'client_ip': '127.0.0.1', 'username': '', 'command_name': 'whoami'},
            {'timestamp_utc': '2026-10-20T01:01:15+00:00', 'event': 'command', 'session_id': 'sess-a', 'client_ip': '127.0.0.1', 'username': '', 'command_name': 'exit'},
            {'timestamp_utc': '2026-10-20T01:01:16+00:00', 'event': 'disconnect', 'session_id': 'sess-a', 'client_ip': '127.0.0.1', 'username': '', 'command_name': ''},
            {'timestamp_utc': '2026-10-20T02:00:00+00:00', 'event': 'connection', 'session_id': 'sess-b', 'client_ip': '127.0.0.2', 'username': '', 'command_name': ''},
            {'timestamp_utc': '2026-10-20T02:05:00+00:00', 'event': 'idle_timeout', 'session_id': 'sess-b', 'client_ip': '127.0.0.2', 'username': '', 'command_name': ''},
        ]
        output = report.render_report(records, 0)
        section = output.split('<h2>Sessions</h2>', 1)[1].split('Latest events', 1)[0]
        self.assertLess(section.index('sess-b'), section.index('sess-a'))  # most recently active first
        self.assertIn('<td>sess-a</td><td>127.0.0.1</td><td>2026-10-20T01:00:00+00:00</td><td>76s</td><td>1</td><td>2</td>', section)
        self.assertIn('&lt;b&gt;root&lt;/b&gt;', section)
        self.assertNotIn('<b>root</b>', section)
        self.assertIn('<td>exit</td>', section)          # the exit command explains the close, not the later disconnect
        self.assertIn('<td>idle_timeout</td>', section)

    def test_report_sessions_handles_open_session(self):
        records = [{'timestamp_utc': '2026-10-20T03:00:00+00:00', 'event': 'connection',
                    'session_id': 'sess-c', 'client_ip': '127.0.0.3', 'username': '', 'command_name': ''}]
        output = report.render_report(records, 0)
        section = output.split('<h2>Sessions</h2>', 1)[1].split('Latest events', 1)[0]
        self.assertIn('<td>sess-c</td><td>127.0.0.3</td>', section)
        self.assertIn('<td>0s</td>', section)
        self.assertIn('<td>-</td>', section)  # no close reason yet

    def test_report_surfaces_refused_sessions(self):
        records = [{'timestamp_utc': '2026-10-20T03:00:00+00:00', 'event': 'session_refused',
                    'session_id': 'sess-r', 'client_ip': '127.0.0.9', 'username': '', 'command_name': ''}]
        output = report.render_report(records, 0)
        self.assertIn('<strong>1</strong><span>Sessions refused (over cap)</span>', output)
        section = output.split('<h2>Sessions</h2>', 1)[1].split('Latest events', 1)[0]
        self.assertIn('<td>sess-r</td>', section)
        self.assertIn('<td>refused (max sessions)</td>', section)

    def test_report_says_when_the_timeline_is_capped(self):
        record = {'timestamp_utc': '2026-10-20T03:00:00+00:00', 'event': 'connection',
                  'session_id': 'sess-t', 'client_ip': '127.0.0.1', 'username': '', 'command_name': ''}
        capped = report.render_report([dict(record) for _ in range(105)], 0)
        self.assertIn('<h2>Latest events (showing 100 of 105)</h2>', capped)
        self.assertIn('<h2>Latest events</h2>', report.render_report([dict(record) for _ in range(3)], 0))

    def test_report_names_the_table_cutoff(self):
        records = [{'timestamp_utc': '2026-10-20T03:00:00+00:00', 'event': 'password_auth',
                    'session_id': 'sess-u', 'client_ip': '127.0.0.1', 'username': f'user{n}', 'command_name': ''}
                   for n in range(25)]
        output = report.render_report(records, 0)
        self.assertIn('<h2>Usernames tried (top 20 of 25)</h2>', output)
        few = report.render_report(records[:5], 0)
        self.assertIn('<h2>Usernames tried</h2>', few)
        self.assertNotIn('top 20 of', few)

    def test_report_handles_empty_events(self):
        self.assertIn('No events yet', report.render_report([]))

    def test_local_ssh_exec_logs_command_not_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            key = honeypot.load_host_key(Path(folder) / 'host_key')
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)
            port = listener.getsockname()[1]
            errors = []
            def serve():
                try:
                    client, address = listener.accept()
                    honeypot.handle_client(client, address, key, honeypot.EventLog(path), timeout=5)
                except Exception as exc:
                    errors.append(exc)
                finally:
                    listener.close()
            worker = threading.Thread(target=serve)
            worker.start()
            transport = paramiko.Transport(('127.0.0.1', port))
            try:
                transport.connect(username='demo', password='dummy-secret', hostkey=key)
                channel = transport.open_session(timeout=3)
                channel.exec_command('ls private-argument')
                data = channel.makefile('rb').read()
                self.assertIn(b'notes.txt', data)
                self.assertEqual(channel.recv_exit_status(), 0)
                try:
                    channel.close()
                except EOFError:
                    pass  # The one-session server may have already closed the transport.
            finally:
                transport.close()
                worker.join(7)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            text = path.read_text()
            self.assertNotIn('dummy-secret', text)
            self.assertNotIn('private-argument', text)
            events = [json.loads(line) for line in text.splitlines()]
            self.assertTrue(any(row['event'] == 'command' and row['command_name'] == 'ls' for row in events))
            self.assertEqual(events[-1]['event'], 'disconnect')
            if __import__('os').name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual((Path(folder)/'host_key').stat().st_mode & 0o777, 0o600)

    def test_report_includes_rotated_logs_oldest_first(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            (Path(folder) / 'events.jsonl.2').write_text(json.dumps(
                {'timestamp_utc': '2026-10-01T00:00:00+00:00', 'event': 'connection', 'session_id': 'oldest1', 'client_ip': '127.0.0.1'}) + '\n')
            (Path(folder) / 'events.jsonl.1').write_text('not-json\n' + json.dumps(
                {'timestamp_utc': '2026-10-02T00:00:00+00:00', 'event': 'connection', 'session_id': 'middle2', 'client_ip': '127.0.0.1'}) + '\n')
            path.write_text(json.dumps(
                {'timestamp_utc': '2026-10-03T00:00:00+00:00', 'event': 'connection', 'session_id': 'newest3', 'client_ip': '127.0.0.1'}) + '\n')
            (Path(folder) / 'events.jsonl.txt').write_text('ignored\n')  # not a rotated suffix
            records, skipped = report.read_events(path)
            self.assertEqual([row['session_id'] for row in records], ['oldest1', 'middle2', 'newest3'])
            self.assertEqual(skipped, 1)

    def test_report_combined_size_limit_counts_rotated_files(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            path.write_text('x' * 100)
            (Path(folder) / 'events.jsonl.1').write_text('x' * 100)  # each file fits; together they do not
            with __import__('unittest.mock', fromlist=['patch']).patch.object(report, 'MAX_LOG_BYTES', 150):
                with self.assertRaises(ValueError):
                    report.read_events(path)

    def test_report_cli_notes_included_rotated_logs(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'events.jsonl'
            out = Path(folder) / 'report.html'
            (Path(folder) / 'events.jsonl.1').write_text(json.dumps(
                {'timestamp_utc': '2026-10-02T00:00:00+00:00', 'event': 'connection', 'session_id': 'older-session', 'client_ip': '127.0.0.1'}) + '\n')
            log.write_text(json.dumps(
                {'timestamp_utc': '2026-10-03T00:00:00+00:00', 'event': 'connection', 'session_id': 'newer-session', 'client_ip': '127.0.0.1'}) + '\n')
            with redirect_stdout(io.StringIO()) as text:
                self.assertEqual(report.main(['--log', str(log), '--output', str(out)]), 0)
            self.assertIn('1 rotated log file', text.getvalue())
            self.assertIn('older-session', out.read_text())

    def test_report_size_and_output_path_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            path.write_text('')
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                report.main(['--log', str(path), '--output', str(path)])
            self.assertEqual(path.read_text(), '')
            with __import__('unittest.mock', fromlist=['patch']).patch.object(report, 'MAX_LOG_BYTES', -1):
                with self.assertRaises(ValueError):
                    report.read_events(path)

    def test_fake_channel_input_and_command_limits(self):
        class Channel:
            def __init__(self, data):
                self.data = data
                self.sent = []
            def settimeout(self, timeout):
                pass
            def recv(self, size):
                chunk, self.data = self.data[:size], self.data[size:]
                return chunk
            def sendall(self, data):
                self.sent.append(data)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            server = honeypot.LabServer(honeypot.EventLog(path), 's', '127.0.0.1')
            channel = Channel(b'a' * 1025)
            honeypot.run_shell(channel, server, __import__('time').monotonic() + 2)
            self.assertIn('input_limit', path.read_text())
            path.write_text('')
            channel = Channel(b'ls\r\n' * 60)
            honeypot.run_shell(channel, server, __import__('time').monotonic() + 2)
            events = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(sum(e['event'] == 'command' for e in events), 40)
            self.assertEqual(events[-1]['event'], 'session_limit')

    def test_interactive_ssh_shell_and_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            key = honeypot.load_host_key(Path(folder) / 'host_key')
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)
            port = listener.getsockname()[1]
            worker = threading.Thread(target=lambda: honeypot.handle_client(
                *listener.accept(), key, honeypot.EventLog(path), timeout=5))
            worker.start()
            transport = paramiko.Transport(('127.0.0.1', port))
            try:
                transport.connect(username='demo', password='dummy', hostkey=key)
                channel = transport.open_session(timeout=3)
                channel.get_pty()
                channel.invoke_shell()
                channel.sendall(b'whoami\r\nexit\r\n')
                output = channel.makefile('rb').read()
                self.assertIn(b'demo\r\n', output)
                try:
                    channel.close()
                except EOFError:
                    pass  # The one-session server may have already closed the transport.
            finally:
                transport.close()
                listener.close()
                worker.join(7)
            self.assertFalse(worker.is_alive())
            events = [json.loads(line) for line in path.read_text().splitlines()]
            commands = [row['command_name'] for row in events if row['event'] == 'command']
            self.assertEqual(commands, ['whoami', 'exit'])


    def test_log_rotation_keeps_limited_backups(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            log = honeypot.EventLog(path, max_bytes=300, backups=2)
            for number in range(20):
                log.write('connection', f's{number}', '127.0.0.1')
            names = sorted(p.name for p in Path(folder).iterdir())
            self.assertEqual(names, ['events.jsonl', 'events.jsonl.1', 'events.jsonl.2'])
            for name in names:
                self.assertLessEqual((Path(folder) / name).stat().st_size, 300)
            newest = json.loads(path.read_text().splitlines()[-1])
            self.assertEqual(newest['session_id'], 's19')
            self.assertEqual(oct((Path(folder) / 'events.jsonl.1').stat().st_mode & 0o777), '0o600')

    def test_log_rotation_zero_backups_and_disabled(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'e.jsonl'
            log = honeypot.EventLog(path, max_bytes=200, backups=0)
            for number in range(10):
                log.write('connection', f's{number}', '127.0.0.1')
            self.assertEqual([p.name for p in Path(folder).iterdir()], ['e.jsonl'])
            self.assertLessEqual(path.stat().st_size, 200)
            plain = Path(folder) / 'plain.jsonl'
            unlimited = honeypot.EventLog(plain, max_bytes=0)
            for number in range(30):
                unlimited.write('connection', f's{number}', '127.0.0.1')
            self.assertEqual(len(plain.read_text().splitlines()), 30)
            with self.assertRaises(ValueError):
                honeypot.EventLog(plain, max_bytes=-1)

    def test_cli_rejects_negative_rotation_options(self):
        for flag in ('--max-log-bytes', '--log-backups'):
            with self.assertRaises(SystemExit) as caught, redirect_stderr(io.StringIO()):
                honeypot.main([flag, '-1'])
            self.assertEqual(caught.exception.code, 2)


    def _interactive(self, folder, timeout, idle, steps):
        path = Path(folder) / 'events.jsonl'
        key = honeypot.load_host_key(Path(folder) / 'host_key')
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)
        worker = threading.Thread(target=lambda: honeypot.handle_client(
            *listener.accept(), key, honeypot.EventLog(path), timeout=timeout, idle_seconds=idle))
        worker.start()
        transport = paramiko.Transport(('127.0.0.1', listener.getsockname()[1]))
        output = b''
        try:
            transport.connect(username='demo', password='dummy', hostkey=key)
            channel = transport.open_session(timeout=3)
            channel.get_pty(); channel.invoke_shell()
            channel.settimeout(1.5)
            for pause, data in steps:
                time.sleep(pause)
                try:
                    channel.sendall(data)
                except (OSError, EOFError):
                    break
            try:
                while True:
                    chunk = channel.recv(1024)
                    if not chunk:
                        break
                    output += chunk
            except (socket.timeout, OSError, EOFError):
                pass
        finally:
            transport.close(); listener.close(); worker.join(7)
        self.assertFalse(worker.is_alive())
        return output, [json.loads(line) for line in path.read_text().splitlines()]

    def test_unknown_command_gets_simulated_response_and_session_stays_open(self):
        with tempfile.TemporaryDirectory() as folder:
            output, events = self._interactive(folder, 10, 10, [(0.2, b'demo\r'), (0.3, b'whoami\r'), (0.3, b'exit\r')])
            self.assertIn(b'command not found (simulated)', output)
            self.assertIn(b'demo\r\nlab$', output)  # the shell kept going after the unknown command
            self.assertEqual([e['command_name'] for e in events if e['event'] == 'command'], ['demo', 'whoami', 'exit'])

    def test_slow_typist_is_not_cut_off_by_total_time_when_active(self):
        with tempfile.TemporaryDirectory() as folder:
            steps = [(0.6, b'demo\r'), (0.6, b'pwd\r'), (0.6, b'exit\r')]
            output, events = self._interactive(folder, 10, 1.5, steps)
            self.assertIn(b'/home/demo', output)
            self.assertFalse([e for e in events if e['event'] in ('idle_timeout', 'session_limit')])

    def test_idle_and_total_limits_explain_why_the_session_ends(self):
        with tempfile.TemporaryDirectory() as folder:
            output, events = self._interactive(folder, 10, 0.8, [(0.1, b'pwd\r')])
            self.assertIn(b'Idle timeout', output)
            self.assertEqual([e['event'] for e in events].count('idle_timeout'), 1)
        with tempfile.TemporaryDirectory() as folder:
            output, events = self._interactive(folder, 1.2, 10, [(0.1, b'pwd\r')])
            self.assertIn(b'Session time limit reached', output)
            self.assertEqual([e['event'] for e in events].count('session_limit'), 1)


    def test_report_filters_by_time_and_session(self):
        rows = [
            {'timestamp_utc': '2026-10-02T23:59:00+00:00', 'session_id': 'aaa111', 'client_ip': '127.0.0.1', 'event': 'connection'},
            {'timestamp_utc': '2026-10-03T10:00:00+00:00', 'session_id': 'bbb222', 'client_ip': '127.0.0.1', 'event': 'connection'},
            {'timestamp_utc': '2026-10-03T10:00:05+00:00', 'session_id': 'bbb222', 'client_ip': '127.0.0.1', 'event': 'command', 'command_name': 'pwd'},
            {'timestamp_utc': 'not a time', 'session_id': 'ccc333', 'client_ip': '127.0.0.1', 'event': 'connection'},
        ]
        since = report.parse_since('2026-10-03')
        self.assertEqual([r['session_id'] for r in report.filter_records(rows, since=since)], ['bbb222', 'bbb222'])
        self.assertEqual(len(report.filter_records(rows, session='bbb')), 2)
        self.assertEqual(len(report.filter_records(rows, since=since, session='aaa')), 0)
        self.assertEqual(len(report.filter_records(rows)), 4)
        self.assertEqual(report.parse_since('2026-10-03T08:00').tzinfo, timezone.utc)
        until = report.parse_since('2026-10-03T10:00:00+00:00')
        self.assertEqual([r['session_id'] for r in report.filter_records(rows, until=until)], ['aaa111', 'bbb222'])
        window = report.filter_records(rows, since=since, until=until)
        self.assertEqual([r['session_id'] for r in window], ['bbb222'])

    def test_report_cli_filters_and_rejects_bad_since(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'events.jsonl'
            out = Path(folder) / 'report.html'
            log.write_text('\n'.join(json.dumps(r) for r in [
                {'timestamp_utc': '2026-10-01T00:00:00+00:00', 'session_id': 'old1', 'client_ip': '10.0.0.1', 'event': 'connection'},
                {'timestamp_utc': '2026-10-04T00:00:00+00:00', 'session_id': 'new1', 'client_ip': '10.0.0.2', 'event': 'connection'}]) + '\n')
            with redirect_stdout(io.StringIO()):
                self.assertEqual(report.main(['--log', str(log), '--output', str(out), '--since', '2026-10-03']), 0)
            page = out.read_text()
            self.assertIn('10.0.0.2', page)
            self.assertNotIn('10.0.0.1', page)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(report.main(['--log', str(log), '--output', str(out), '--until', '2026-10-03']), 0)
            page = out.read_text()
            self.assertIn('10.0.0.1', page)
            self.assertNotIn('10.0.0.2', page)
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                report.main(['--log', str(log), '--output', str(out), '--since', 'yesterday'])
            self.assertEqual(caught.exception.code, 2)
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                report.main(['--log', str(log), '--output', str(out), '--until', 'next week'])
            self.assertEqual(caught.exception.code, 2)


    def test_graceful_close_half_shuts_then_waits_for_peer(self):
        left, right = socket.socketpair()
        received = []
        peer_done = threading.Event()

        class Transport:
            def is_active(self):
                return not peer_done.is_set()

        def peer():
            while True:
                chunk = right.recv(1024)
                received.append(chunk)
                if not chunk:
                    break
            right.close()
            peer_done.set()

        threading.Thread(target=peer).start()
        left.sendall(b'final channel bytes')
        start = time.monotonic()
        honeypot.close_session_gracefully(left, Transport(), start + 10, grace=1)
        elapsed = time.monotonic() - start
        left.close()
        self.assertEqual(b''.join(received), b'final channel bytes')
        self.assertEqual(received[-1], b'')  # the peer saw a clean EOF right after the data
        self.assertLess(elapsed, 1)  # it returned as soon as the peer closed, not at the grace limit

    def test_graceful_close_is_bounded_when_peer_stays_open(self):
        left, right = socket.socketpair()

        class Transport:
            def is_active(self):
                return True

        start = time.monotonic()
        honeypot.close_session_gracefully(left, Transport(), start + 10, grace=0.3)
        elapsed = time.monotonic() - start
        left.close()
        right.close()
        self.assertGreaterEqual(elapsed, 0.25)
        self.assertLess(elapsed, 0.9)  # a silent peer never stalls teardown

    def test_interactive_session_close_leaves_no_socket_error(self):
        records = []

        class Handler(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        logger = logging.getLogger('paramiko')
        handler = Handler(level=logging.ERROR)
        logger.addHandler(handler)
        try:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'events.jsonl'
                key = honeypot.load_host_key(Path(folder) / 'host_key')
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)
                worker = threading.Thread(target=lambda: honeypot.handle_client(
                    *listener.accept(), key, honeypot.EventLog(path), timeout=5))
                worker.start()
                transport = paramiko.Transport(('127.0.0.1', listener.getsockname()[1]))
                try:
                    transport.connect(username='demo', password='dummy', hostkey=key)
                    channel = transport.open_session(timeout=3)
                    channel.get_pty()
                    channel.invoke_shell()
                    channel.sendall(b'whoami\r\nexit\r\n')
                    output = channel.makefile('rb').read()
                    self.assertIn(b'demo\r\n', output)
                    # The server's orderly half-close lets the client transport
                    # end on its own, without the test forcing transport.close().
                    deadline = time.monotonic() + 2
                    while transport.is_active() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertFalse(transport.is_active())
                finally:
                    transport.close()
                    listener.close()
                    worker.join(7)
                self.assertFalse(worker.is_alive())
                events = [json.loads(line) for line in path.read_text().splitlines()]
                self.assertEqual(events[-1]['event'], 'disconnect')
        finally:
            logger.removeHandler(handler)
        self.assertFalse([m for m in records if 'Socket exception' in m])


    def test_exit_and_logout_explain_the_close(self):
        shell = honeypot.FakeShell('demo')
        for word in ('exit', 'logout'):
            name, args, response, stop = shell.respond(word)
            self.assertEqual(response, 'closing the lab session.\r\n')
            self.assertTrue(stop)
        with tempfile.TemporaryDirectory() as folder:
            output, events = self._interactive(folder, 10, 10, [(0.2, b'exit\r')])
            self.assertIn(b'closing the lab session.', output)
            self.assertEqual([e['command_name'] for e in events if e['event'] == 'command'], ['exit'])
            self.assertEqual(events[-1]['event'], 'disconnect')



    def test_concurrent_sessions_are_served_in_parallel(self):
        """A second caller is served while the first session is still open."""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            key = honeypot.load_host_key(Path(folder) / 'host_key')
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0)); listener.listen(5); listener.settimeout(1)
            port = listener.getsockname()[1]
            server = threading.Thread(target=honeypot.serve,
                                      args=(listener, key, honeypot.EventLog(path)), daemon=True)
            server.start()
            first = paramiko.Transport(('127.0.0.1', port))
            try:
                first.connect(username='alice', password='dummy', hostkey=key)
                shell = first.open_session(timeout=5)
                shell.get_pty(); shell.invoke_shell(); shell.settimeout(5)
                shell.sendall(b'whoami\r\n')
                seen = b''
                deadline = time.monotonic() + 5
                while b'alice\r\n' not in seen and time.monotonic() < deadline:
                    try:
                        seen += shell.recv(256)
                    except socket.timeout:
                        break
                self.assertIn(b'alice\r\n', seen)  # first session is logged in and stays open
                # With one-at-a-time handling this second handshake would stall until the first exits.
                second = paramiko.Transport(('127.0.0.1', port))
                try:
                    second.connect(username='bob', password='dummy', hostkey=key)
                    channel = second.open_session(timeout=5)
                    channel.exec_command('hostname')
                    self.assertIn(b'lab-vm', channel.makefile('rb').read())
                    try:
                        channel.close()
                    except EOFError:
                        pass
                finally:
                    second.close()
                shell.sendall(b'exit\r\n')
                try:
                    shell.close()
                except EOFError:
                    pass
            finally:
                first.close()
                listener.close()
                server.join(5)
            self.assertFalse(server.is_alive())
            time.sleep(0.2)  # let session threads flush their final events
            events = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len({row['session_id'] for row in events if row['event'] == 'connection'}), 2)
            names = sorted(row['username'] for row in events if row['event'] == 'password_auth')
            self.assertEqual(names, ['alice', 'bob'])
            self.assertTrue(any(row['event'] == 'command' and row['command_name'] == 'hostname' for row in events))



    def test_over_cap_caller_is_refused_and_logged(self):
        """With the session cap reached, a new caller is turned away, not queued."""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            key = honeypot.load_host_key(Path(folder) / 'host_key')
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0)); listener.listen(5); listener.settimeout(1)
            port = listener.getsockname()[1]
            server = threading.Thread(target=honeypot.serve,
                                      args=(listener, key, honeypot.EventLog(path)),
                                      kwargs={'max_sessions': 1}, daemon=True)
            server.start()
            first = paramiko.Transport(('127.0.0.1', port))
            try:
                first.connect(username='alice', password='dummy', hostkey=key)
                shell = first.open_session(timeout=5)
                shell.get_pty(); shell.invoke_shell(); shell.settimeout(5)
                shell.sendall(b'whoami\r\n')
                seen = b''
                deadline = time.monotonic() + 5
                while b'alice\r\n' not in seen and time.monotonic() < deadline:
                    try:
                        seen += shell.recv(256)
                    except socket.timeout:
                        break
                self.assertIn(b'alice\r\n', seen)  # cap of 1 is now fully used
                refused = paramiko.Transport(('127.0.0.1', port))
                try:
                    with self.assertRaises(paramiko.SSHException):
                        refused.connect(username='bob', password='dummy', hostkey=key)
                finally:
                    refused.close()
                shell.sendall(b'exit\r\n')
                try:
                    shell.close()
                except EOFError:
                    pass
            finally:
                first.close()
                listener.close()
                server.join(5)
            self.assertFalse(server.is_alive())
            time.sleep(0.2)
            events = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertTrue(any(row['event'] == 'session_refused' and row.get('reason') == 'max_sessions_reached'
                                for row in events))
            self.assertEqual([row['username'] for row in events if row['event'] == 'password_auth'], ['alice'])

    def test_serve_rejects_invalid_max_sessions(self):
        with tempfile.TemporaryDirectory() as folder:
            listener = socket.socket()
            try:
                with self.assertRaises(ValueError):
                    honeypot.serve(listener, None, honeypot.EventLog(Path(folder) / 'e.jsonl'),
                                 max_sessions=0)
            finally:
                listener.close()

    def test_cli_rejects_zero_max_sessions(self):
        with tempfile.TemporaryDirectory() as folder:
            stderr = io.StringIO()
            with self.assertRaises(SystemExit), redirect_stderr(stderr):
                honeypot.main(['--log', str(Path(folder) / 'e.jsonl'),
                               '--host-key', str(Path(folder) / 'k'), '--max-sessions', '0'])
            self.assertIn('at least 1', stderr.getvalue())



    def test_report_cli_rejects_since_after_until(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'events.jsonl'
            log.write_text('')
            stderr = io.StringIO()
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                report.main(['--log', str(log), '--output', str(Path(folder) / 'r.html'),
                             '--since', '2026-10-05', '--until', '2026-10-03'])
            self.assertEqual(caught.exception.code, 2)
            self.assertIn('must not be after', stderr.getvalue())

    def test_report_notes_active_filters_and_escapes_them(self):
        rows = [{'timestamp_utc': '2026-10-03T10:00:00+00:00', 'session_id': 'abc123',
                 'client_ip': '127.0.0.1', 'event': 'connection', 'username': '', 'command_name': ''}]
        plain = report.render_report(rows)
        self.assertNotIn('Showing only events', plain)
        since = report.parse_since('2026-10-03')
        until = report.parse_since('2026-10-04')
        page = report.render_report(rows, since=since, until=until, session='ab"<')
        self.assertIn('Showing only events from 2026-10-03T00:00:00+00:00; until 2026-10-04T00:00:00+00:00', page)
        self.assertIn('session starts with &quot;ab&quot;&lt;', page)
        self.assertNotIn('ab"<', page)  # the raw session text must not reach the HTML


if __name__ == '__main__':
    unittest.main()
