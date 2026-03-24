#!/usr/bin/env python3
"""Select an ESP32-like serial port by rank (lowest/highest), upload, then monitor.

Usage:
  python3 scripts/flash_and_monitor.py 1
  python3 scripts/flash_and_monitor.py 2
  python3 scripts/flash_and_monitor.py 1 --upload-only
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


ESP32_HINTS = (
    "esp32",
    "espressif",
    "usb jtag",
    "cp210",
    "ch340",
    "ch910",
    "silicon labs",
    "wch",
    "ftdi",
    "vid:pid=1a86",  # WCH CH340/CH910
    "vid:pid=10c4",  # Silicon Labs CP210x
    "vid:pid=303a",  # Espressif USB
)


@dataclass
class PortInfo:
    port: str
    description: str
    hwid: str
    manufacturer: str

    @property
    def searchable(self) -> str:
        return " ".join([self.port, self.description, self.hwid, self.manufacturer]).lower()


def run_checked(cmd: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=True)


def list_ports_via_pio() -> List[PortInfo]:
    proc = run_checked(["pio", "device", "list", "--json-output"])
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse PlatformIO JSON output: {exc}") from exc

    ports: List[PortInfo] = []
    for item in payload:
        ports.append(
            PortInfo(
                port=str(item.get("port", "")).strip(),
                description=str(item.get("description", "")).strip(),
                hwid=str(item.get("hwid", "")).strip(),
                manufacturer=str(item.get("manufacturer", "")).strip(),
            )
        )
    return [p for p in ports if p.port]


def _pids_via_lsof(port: str) -> List[int]:
    try:
        proc = subprocess.run(["lsof", "-t", port], text=True, capture_output=True, check=False)
    except FileNotFoundError:
        return []
    if proc.returncode != 0:
        return []
    out = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    pids: List[int] = []
    for item in out:
        if item.isdigit():
            pids.append(int(item))
    return sorted(set(pids))


def _pids_via_fuser(port: str) -> List[int]:
    try:
        proc = subprocess.run(["fuser", port], text=True, capture_output=True, check=False)
    except FileNotFoundError:
        return []
    if proc.returncode not in (0, 1):
        return []
    text = (proc.stdout + " " + proc.stderr).strip()
    matches = re.findall(r"\b\d+\b", text)
    return sorted({int(m) for m in matches})


def pids_holding_port(port: str) -> List[int]:
    pids = _pids_via_lsof(port)
    if pids:
        return pids
    return _pids_via_fuser(port)


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop_port_owners(port: str, timeout_seconds: float = 2.0) -> List[int]:
    pids = pids_holding_port(port)
    if not pids:
        return []

    me = os.getpid()
    targets = [pid for pid in pids if pid != me]
    if not targets:
        return []

    for pid in targets:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        alive = [pid for pid in targets if _is_alive(pid)]
        if not alive:
            break
        time.sleep(0.1)

    remaining = [pid for pid in targets if _is_alive(pid)]
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass

    return targets


def looks_like_esp32(port: PortInfo) -> bool:
    text = port.searchable
    return any(hint in text for hint in ESP32_HINTS)


def numeric_port_key(dev_path: str) -> Tuple[int, str, int]:
    # Prefer ttyUSB/ttyACM numeric ordering; fallback to lexical.
    m = re.search(r"/dev/(tty(?:USB|ACM))(\d+)$", dev_path)
    if m:
        prefix = m.group(1)
        number = int(m.group(2))
        prefix_rank = 0 if prefix == "ttyUSB" else 1
        return (0, prefix_rank, number)
    return (1, dev_path, 0)


def select_port(candidates: Iterable[PortInfo], which: int) -> PortInfo:
    pool = sorted(candidates, key=lambda p: numeric_port_key(p.port))
    if not pool:
        raise RuntimeError("No ESP32-like serial devices found.")
    if which == 1:
        return pool[0]
    if which == 2:
        return pool[-1]
    raise ValueError("Selector must be 1 (lowest) or 2 (highest).")


def find_platformio_root(start: str) -> Optional[str]:
    cur = os.path.abspath(start)
    while True:
        if os.path.isfile(os.path.join(cur, "platformio.ini")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Upload + monitor ESP32 by selecting lowest/highest ESP32-like serial port.")
    parser.add_argument("selector", type=int, choices=[1, 2], help="1 = lowest serial port, 2 = highest serial port")
    parser.add_argument("--env", default="esp32dev", help="PlatformIO environment (default: esp32dev)")
    parser.add_argument("--baud", type=int, default=115200, help="Serial monitor baud (default: 115200)")
    parser.add_argument("--dry-run", action="store_true", help="Print chosen port and exit")
    parser.add_argument("--upload-only", action="store_true", help="Upload only, do not start monitor")
    parser.add_argument("--monitor-only", action="store_true", help="Start monitor only, skip upload")
    parser.add_argument("--kill-port-owner", action="store_true", help="Try to stop processes using the selected serial port before upload/monitor")
    args = parser.parse_args()

    if args.upload_only and args.monitor_only:
        print("Error: --upload-only and --monitor-only are mutually exclusive.", file=sys.stderr)
        return 2

    project_root = find_platformio_root(os.getcwd())
    if not project_root:
        print("Error: could not find platformio.ini from current directory.", file=sys.stderr)
        return 2

    try:
        ports = list_ports_via_pio()
    except Exception as exc:
        print(f"Error listing serial devices via PlatformIO: {exc}", file=sys.stderr)
        return 2

    esp32_ports = [p for p in ports if looks_like_esp32(p)]
    if not esp32_ports:
        print("No ESP32-like ports found. Available ports:", file=sys.stderr)
        for p in ports:
            print(f"  - {p.port}: {p.description} [{p.hwid}]", file=sys.stderr)
        return 3

    selected = select_port(esp32_ports, args.selector)

    print(f"Selected port ({args.selector}): {selected.port}")
    print(f"  Description: {selected.description}")
    if selected.manufacturer:
        print(f"  Manufacturer: {selected.manufacturer}")
    if selected.hwid:
        print(f"  HWID: {selected.hwid}")

    if args.dry_run:
        return 0

    if args.kill_port_owner:
        killed = stop_port_owners(selected.port)
        if killed:
            print(f"Stopped processes on {selected.port}: {', '.join(str(pid) for pid in killed)}")
            # Give udev/driver lock state a brief moment to settle.
            time.sleep(0.25)
        else:
            print(f"No active process lock found on {selected.port}.")

    if not args.monitor_only:
        upload_cmd = [
            "pio", "run", "-e", args.env, "-t", "upload", "--upload-port", selected.port
        ]
        print("\nUploading:")
        print("  " + " ".join(upload_cmd))
        upload_proc = subprocess.run(upload_cmd, cwd=project_root)
        if upload_proc.returncode != 0:
            return upload_proc.returncode

    if args.upload_only:
        print("Upload complete (--upload-only).")
        return 0

    monitor_cmd = [
        "pio", "device", "monitor", "--port", selected.port, "--baud", str(args.baud)
    ]
    print("\nStarting monitor:")
    print("  " + " ".join(monitor_cmd))
    os.execvp(monitor_cmd[0], monitor_cmd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


