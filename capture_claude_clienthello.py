#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import tempfile
import time


def read_first_tls_record(connection):
    data = bytearray()
    while len(data) < 5:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    if len(data) < 5:
        raise RuntimeError("short TLS record header")
    if data[0] != 0x16:
        raise RuntimeError(f"first record is not TLS handshake: 0x{data[0]:02x}")
    record_length = int.from_bytes(data[3:5], "big")
    while len(data) < 5 + record_length:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    if len(data) < 5 + record_length:
        raise RuntimeError("short TLS record payload")
    record = bytes(data[:5 + record_length])
    if len(record) < 9 or record[5] != 1:
        raise RuntimeError("first TLS handshake is not ClientHello")
    return record


def terminate_process(process):
    if process.poll() is not None:
        return process.communicate()[1]
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        return process.communicate(timeout=3)[1]
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.communicate(timeout=3)[1]


def locate_claude(requested):
    if requested:
        return requested
    executable = shutil.which("claude") or shutil.which("claude.exe")
    if not executable:
        raise RuntimeError("Claude executable not found; use --claude /absolute/path/to/claude")
    return executable


def main():
    parser = argparse.ArgumentParser(description="Capture Debian Claude Code's first ClientHello")
    parser.add_argument("--claude", help="Claude executable; defaults to claude in PATH")
    parser.add_argument(
        "--output",
        default="/tmp/claude-debian-capture/claude-debian.json",
        help="0600 JSON output path",
    )
    parser.add_argument("--prompt", default="hi")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()

    claude = locate_claude(args.claude)
    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output.parent, 0o700)

    version_process = subprocess.run(
        [claude, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    version = (version_process.stdout or version_process.stderr).strip().splitlines()[0]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.setblocking(False)
        port = listener.getsockname()[1]

        environment = os.environ.copy()
        for name in (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
            "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
        ):
            environment.pop(name, None)
        environment["NO_PROXY"] = "127.0.0.1,localhost"
        environment["no_proxy"] = "127.0.0.1,localhost"
        environment["ANTHROPIC_BASE_URL"] = f"https://127.0.0.1:{port}"
        environment["ANTHROPIC_API_KEY"] = "sk-ant-capture-dummy"
        environment["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
        environment["CLAUDE_CODE_DISABLE_TERMINAL_TITLE"] = "1"
        environment["CLAUDE_CODE_ENTRYPOINT"] = "claude-desktop-3p"
        environment["CI"] = "1"
        environment["IS_DEMO"] = "1"

        with tempfile.TemporaryDirectory(prefix="claude-clienthello-", dir="/tmp") as work_dir:
            process = subprocess.Popen(
                [claude, "-p", args.prompt],
                cwd=work_dir,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            record = None
            deadline = time.monotonic() + args.timeout
            try:
                while time.monotonic() < deadline:
                    try:
                        connection, _ = listener.accept()
                    except BlockingIOError:
                        if process.poll() is not None:
                            stderr = process.communicate()[1].strip()
                            raise RuntimeError(
                                f"Claude exited before connecting (code {process.returncode}): {stderr[-1000:]}"
                            )
                        time.sleep(0.05)
                        continue
                    with connection:
                        connection.settimeout(5)
                        record = read_first_tls_record(connection)
                    break
                if record is None:
                    stderr = terminate_process(process).strip()
                    raise TimeoutError(
                        f"Claude did not connect to the loopback listener within {args.timeout:g}s: {stderr[-1000:]}"
                    )
            finally:
                if process.poll() is None:
                    terminate_process(process)

    payload = {
        "raw_hex": record.hex(),
        "source": "debian-loopback-capture",
        "claude_version": version,
        "target": "https://127.0.0.1",
        "record_bytes": len(record),
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(output, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w") as file:
            json.dump(payload, file, indent=2)
            file.write("\n")
    except Exception:
        os.close(descriptor)
        raise
    os.chmod(output, 0o600)
    print(f"saved {len(record)} bytes to {output}")
    print(f"claude_version={version}")
    print(f"raw_hex_length={len(payload['raw_hex'])}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        raise SystemExit(f"error: {error}")
