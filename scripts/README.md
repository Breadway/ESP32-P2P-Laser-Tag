# Helper Scripts

## `flash_and_monitor.py`

Pick one ESP32 serial port by rank and run upload + monitor in one command.

- `1` = lowest `/dev/ttyUSB*` or `/dev/ttyACM*`
- `2` = highest `/dev/ttyUSB*` or `/dev/ttyACM*`

The script discovers ports via `pio device list --json-output` and filters for ESP32-like USB adapters (Espressif/CP210x/CH340/etc).

### Usage

```bash
cd '/home/breadway/Documents/Laser Tag'
python3 scripts/flash_and_monitor.py 1
python3 scripts/flash_and_monitor.py 2
```

### Useful options

```bash
# Just show which port would be selected
python3 scripts/flash_and_monitor.py 1 --dry-run

# Use a different PlatformIO environment
python3 scripts/flash_and_monitor.py 1 --env esp32debugger

# Different monitor baud
python3 scripts/flash_and_monitor.py 1 --baud 921600

# Upload only (non-interactive)
python3 scripts/flash_and_monitor.py 1 --upload-only

# Monitor only (skip upload)
python3 scripts/flash_and_monitor.py 2 --monitor-only

# Attempt to stop any process holding the selected serial port first
python3 scripts/flash_and_monitor.py 1 --kill-port-owner
```

If upload fails with "port is busy", close any active monitor on that port and retry.

## `serial_smoke_test.py`

Runs an automated command sequence across two serial ports to exercise lobby/start,
sync/fire command paths, packet counters, and local reset behavior.

Install dependency:

```bash
cd '/home/breadway/Documents/Laser Tag'
python3 -m pip install -r scripts/requirements.txt
```

Run smoke test (example ports):

```bash
cd '/home/breadway/Documents/Laser Tag'
python3 scripts/serial_smoke_test.py --port1 /dev/ttyUSB1 --port2 /dev/ttyUSB6
```

The script writes a session log to `scripts/serial_test_session.log` by default.

