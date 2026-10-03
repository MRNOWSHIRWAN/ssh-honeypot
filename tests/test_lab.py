import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr

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


if __name__ == '__main__':
    unittest.main()
