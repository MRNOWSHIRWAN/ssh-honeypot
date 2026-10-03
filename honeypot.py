"""Loopback-only SSH learning lab. No subprocesses or real shell access."""
import argparse
from collections import deque
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import threading
import time
import uuid

import paramiko

MAX_INPUT = 1024
MAX_COMMANDS = 40
SESSION_SECONDS = 300  # hard cap on one session, including login
IDLE_SECONDS = 60      # a session with no input for this long is closed
DEFAULT_MAX_LOG_BYTES = 1_000_000
DEFAULT_BACKUPS = 3


def bounded(value, size=128):
    return ''.join(c for c in str(value) if c.isprintable())[:size]


class EventLog:
    """Append-only JSON Lines log with size-based rotation (events.jsonl -> .1 -> .2 ...)."""

    def __init__(self, path, max_bytes=DEFAULT_MAX_LOG_BYTES, backups=DEFAULT_BACKUPS):
        if max_bytes < 0 or backups < 0:
            raise ValueError('max_bytes and backups must not be negative')
        self.path = Path(path)
        self.max_bytes = max_bytes  # 0 disables rotation
        self.backups = backups      # 0 means the full log is discarded on rotation
        self.lock = threading.Lock()

    def _rotate(self):
        """Shift old files up by one; the oldest beyond `backups` is deleted."""
        if self.backups == 0:
            self.path.unlink()
            return
        oldest = self.path.with_name(f'{self.path.name}.{self.backups}')
        oldest.unlink(missing_ok=True)
        for number in range(self.backups - 1, 0, -1):
            source = self.path.with_name(f'{self.path.name}.{number}')
            if source.exists():
                os.replace(source, self.path.with_name(f'{self.path.name}.{number + 1}'))
        os.replace(self.path, self.path.with_name(f'{self.path.name}.1'))

    def write(self, event, session, client_ip, **fields):
        record = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
                      event=event, session_id=session, client_ip=client_ip, **fields)
        line = json.dumps(record, ensure_ascii=True) + '\n'
        with self.lock:
            if self.max_bytes and self.path.exists() and self.path.stat().st_size + len(line) > self.max_bytes:
                self._rotate()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, 'a', encoding='utf-8') as stream:
                stream.write(line)


class FakeShell:
    """Fixed responses only. Never evaluate a submitted string."""
    def __init__(self, username):
        self.username = bounded(username)

    def respond(self, text):
        parts = bounded(text, MAX_INPUT).split()
        name = parts[0][:64] if parts else ''
        args = max(0, len(parts) - 1)
        if not name:
            return name, args, '', False
        responses = {
            'help': 'Simulated commands: help, whoami, pwd, ls, uname, exit\r\n',
            'whoami': self.username + '\r\n',
            'pwd': '/home/demo\r\n',
            'ls': 'notes.txt\r\n',
            'uname': 'Linux (simulated lab)\r\n',
        }
        return name, args, responses.get(name, 'command not found (simulated)\r\n'), name in ('exit', 'logout')


class LabServer(paramiko.ServerInterface):
    def __init__(self, log, session, client_ip):
        self.log, self.session, self.client_ip = log, session, client_ip
        self.username = 'demo'
        self.shell_requested = threading.Event()
        self.exec_command = None
        self.channels = 0
        self.pending = deque(maxlen=20)
        self.pending_lock = threading.Lock()

    def enqueue(self, event, **fields):
        # Paramiko callbacks must not block on file I/O.
        with self.pending_lock:
            self.pending.append((event, fields))

    def flush(self):
        with self.pending_lock:
            pending = list(self.pending)
            self.pending.clear()
        for event, fields in pending:
            self.log.write(event, self.session, self.client_ip, **fields)

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        self.username = bounded(username)
        # Do not retain, hash, compare, or log the password.
        self.enqueue('password_auth', username=self.username, password='[REDACTED]')
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session' and self.channels == 0:
            self.channels += 1
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_requested.set()
        return True

    def check_channel_exec_request(self, channel, command):
        if len(command) > MAX_INPUT:
            self.enqueue('input_limit')
            return False
        self.exec_command = command.decode('utf-8', errors='replace')
        self.shell_requested.set()
        return True


def command_response(channel, server, shell, command):
    name, args, response, stop = shell.respond(command)
    if name:
        server.log.write('command', server.session, server.client_ip,
                         username=server.username, command_name=name, argument_count=args)
    if response and not stop:
        channel.sendall(response.encode('utf-8'))
    return stop


def run_shell(channel, server, deadline, idle_seconds=IDLE_SECONDS):
    shell = FakeShell(server.username)
    channel.settimeout(0.2)  # short so deadlines are noticed promptly
    if server.exec_command is not None:
        command_response(channel, server, shell, server.exec_command)
        server.exec_command = None
        return
    channel.sendall(b'SSH Honeypot Lab - simulated shell, no commands execute.\r\nlab$ ')
    buffer = bytearray()
    commands = 0
    last_cr = False
    idle_deadline = time.monotonic() + idle_seconds
    while time.monotonic() < deadline and commands < MAX_COMMANDS:
        server.flush()
        if time.monotonic() >= idle_deadline:
            channel.sendall(b'\r\nIdle timeout, closing the lab session.\r\n')
            server.log.write('idle_timeout', server.session, server.client_ip)
            return
        try:
            chunk = channel.recv(256)
        except socket.timeout:
            continue
        if not chunk:
            return
        idle_deadline = time.monotonic() + idle_seconds
        for byte in chunk:
            if byte in (10, 13):
                if byte == 10 and last_cr:
                    last_cr = False
                    continue
                last_cr = byte == 13
                command = buffer.decode('utf-8', errors='replace')
                buffer.clear()
                commands += 1
                if command_response(channel, server, shell, command):
                    return
                if commands >= MAX_COMMANDS:
                    break
                channel.sendall(b'lab$ ')
            elif byte in (8, 127):
                if buffer:
                    buffer.pop()
            elif byte >= 32:
                last_cr = False
                buffer.append(byte)
                if len(buffer) > MAX_INPUT:
                    buffer.clear()
                    server.log.write('input_limit', server.session, server.client_ip)
                    return
    # Tell the user why the session ends instead of dropping the connection silently.
    try:
        reason = 'Command limit reached' if commands >= MAX_COMMANDS else 'Session time limit reached'
        channel.sendall(f'\r\n{reason}, closing the lab session.\r\n'.encode())
    except (OSError, EOFError):
        pass
    server.log.write('session_limit', server.session, server.client_ip)


def handle_client(client, address, key, log, timeout=SESSION_SECONDS, idle_seconds=IDLE_SECONDS):
    session = uuid.uuid4().hex
    ip = address[0]
    transport = None
    server = LabServer(log, session, ip)
    deadline = time.monotonic() + timeout
    try:
        log.write('connection', session, ip)
        client.settimeout(timeout)
        transport = paramiko.Transport(client)
        transport.local_version = 'SSH-2.0-SSH_Honeypot_Lab'
        transport.add_server_key(key)
        ready = threading.Event()
        transport.start_server(event=ready, server=server)
        while not ready.wait(0.1):
            server.flush()
            if time.monotonic() >= deadline:
                return
        while transport.is_active() and time.monotonic() < deadline:
            server.flush()
            channel = transport.accept(timeout=0.2)
            if channel is None:
                continue
            with channel:
                while not server.shell_requested.wait(0.1):
                    server.flush()
                    if channel.closed or time.monotonic() >= deadline:
                        return
                server.flush()
                run_shell(channel, server, deadline, idle_seconds)
                if not channel.closed:
                    channel.send_exit_status(0)
            # Allow the client to acknowledge channel close before closing TCP.
            # The grace window is bounded and never extends the session deadline.
            grace_deadline = min(deadline, time.monotonic() + 0.5)
            while transport.is_active() and time.monotonic() < grace_deadline:
                time.sleep(0.01)
            return
    except (paramiko.SSHException, OSError, EOFError):
        log.write('session_error', session, ip, reason='transport_or_io_error')
    finally:
        if transport is not None:
            transport.close()
        client.close()
        server.flush()
        log.write('disconnect', session, ip)


def load_host_key(path):
    path = Path(path)
    if path.exists():
        return paramiko.RSAKey.from_private_key_file(str(path))
    key = paramiko.RSAKey.generate(2048)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        key.write_private_key(stream)
    return key


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1', help='loopback IP literal only')
    parser.add_argument('--port', default=2222, type=int)
    parser.add_argument('--log', type=Path, default=Path('events.jsonl'))
    parser.add_argument('--host-key', type=Path, default=Path('host_key'))
    parser.add_argument('--max-log-bytes', type=int, default=DEFAULT_MAX_LOG_BYTES,
                        help='rotate the event log before it exceeds this size; 0 disables rotation (default 1000000)')
    parser.add_argument('--log-backups', type=int, default=DEFAULT_BACKUPS,
                        help='rotated files to keep as events.jsonl.1, .2 ...; 0 discards the full log (default 3)')
    args = parser.parse_args(argv)
    try:
        ip = ipaddress.ip_address(args.host)
        if not ip.is_loopback or not 1 <= args.port <= 65535:
            raise ValueError('use a loopback IP and a port from 1 to 65535')
        if args.max_log_bytes < 0 or args.log_backups < 0:
            raise ValueError('--max-log-bytes and --log-backups must not be negative')
    except ValueError as exc:
        parser.error(str(exc))
    try:
        key = load_host_key(args.host_key)
        log = EventLog(args.log, args.max_log_bytes, args.log_backups)
        with socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((args.host, args.port))
            listener.listen(5)
            listener.settimeout(1)
            print(f'Local lab listening on {args.host}:{args.port}. Ctrl+C stops. Passwords/arguments are not stored.', flush=True)
            while True:
                try:
                    client, address = listener.accept()
                except socket.timeout:
                    continue
                handle_client(client, address, key, log)
    except KeyboardInterrupt:
        return 0
    except (OSError, paramiko.SSHException) as exc:
        print(f'Cannot run local lab: {type(exc).__name__}. Check port, log and host-key paths.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
