#!/usr/bin/env python3
"""Automated serial smoke test for two ESP32 nodes.

This script opens two serial ports, sends debug commands, and captures output.
It is meant for bench testing without full hardware.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import serial


def read_all(ser: serial.Serial, window: float = 0.6) -> str:
    end = time.time() + window
    chunks: list[bytes] = []
    while time.time() < end:
        n = ser.in_waiting
        if n:
            chunks.append(ser.read(n))
        else:
            time.sleep(0.02)
    return b"".join(chunks).decode("utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description="Run an automated two-node serial smoke test")
    ap.add_argument("--port1", required=True, help="First serial port")
    ap.add_argument("--port2", required=True, help="Second serial port")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--log", default="scripts/serial_test_session.log")
    ap.add_argument("--start-wait", type=float, default=4.0, help="Seconds to wait after sending ready commands")
    ap.add_argument("--skip-local-reset", action="store_true", help="Skip the local doReset() step")
    args = ap.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("=== serial integration test session ===\n", encoding="utf-8")

    ports = [args.port1, args.port2]
    serials: dict[str, serial.Serial] = {}

    def log(msg: str) -> None:
        print(msg)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(msg + "\n")

    def send(port: str, cmd: str, settle: float = 0.9) -> None:
        s = serials[port]
        s.write(cmd.encode("ascii"))
        s.flush()
        out = read_all(s, settle)
        log(f"\n--- {port} <= {cmd!r} ---")
        log(out.rstrip() if out.strip() else "(no output)")

    try:
        for p in ports:
            s = serial.Serial(p, baudrate=args.baud, timeout=0.05)
            s.reset_input_buffer()
            s.reset_output_buffer()
            serials[p] = s

        # Boot capture
        for p in ports:
            out = read_all(serials[p], 2.0)
            log(f"\n=== Boot capture {p} ===")
            log(out.rstrip() if out.strip() else "(no output)")

        # Quiet + clear counters + baseline snapshot
        for p in ports:
            send(p, "0")
            send(p, "z")
            send(p, "i")

        # Team select and ready
        send(ports[0], "a")
        send(ports[1], "b")
        send(ports[0], "r")
        send(ports[1], "r")

        log(f"\n=== Waiting {args.start_wait:.1f}s for STARTING/IN_GAME transitions ===")
        time.sleep(args.start_wait)

        for p in ports:
            out = read_all(serials[p], 1.0)
            log(f"\n=== Post-start capture {p} ===")
            log(out.rstrip() if out.strip() else "(no output)")

        # In-game smoke commands
        for p in ports:
            send(p, "f")
        for p in ports:
            send(p, "s")

        # Diagnostics dump
        for p in ports:
            send(p, "k")
            send(p, "w")
            send(p, "i")

        # Local reset on node1 (optional)
        if not args.skip_local_reset:
            send(ports[0], "d")
            time.sleep(1.0)
            for p in ports:
                out = read_all(serials[p], 0.8)
                log(f"\n=== After local reset capture {p} ===")
                log(out.rstrip() if out.strip() else "(no output)")

    finally:
        for s in serials.values():
            try:
                s.close()
            except Exception:
                pass

    print(f"\nSESSION_LOG {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


