# Progress Report

Date: 2026-03-24
Source: `scripts/serial_test_session.log` (attached)
Scope: Findings based only on the attached serial smoke-test log.

## Task Receipt + Plan

- [x] Read the attached serial test session evidence.
- [x] Classify what is confirmed vs not confirmed.
- [x] Split findings into `main.cpp` behavior and overall project status.
- [x] Record the report in this file.

## Confirmed Working (`src/main.cpp`)

- Debug serial command handling is active on at least one node (`/dev/ttyUSB1`):
  - `0` -> quiet mode response observed.
  - `z` -> counter clear response observed.
  - `i` -> snapshot + peer + packet counters observed.
  - `a` -> team set to RED observed.
  - `r` -> ready vote command accepted.
  - `f` -> in-game fire command accepted (`[DBG] fireGun()`).
  - `s` -> sync request command accepted.
  - `k` -> packet counter print observed.
  - `w` -> radio status + known peer print observed.
- Runtime state machine on `/dev/ttyUSB1` was already in `IN_GAME` and stayed stable during commands:
  - Snapshot shows `st=IN_GAME`, `team=1`, `id=0`, `peers=1`, `ready=2/2`.
- ESP-NOW connectivity indicators on `/dev/ttyUSB1` are healthy in this sample:
  - `wifi=6`, `mode=1`, `ch=1`, `bcastPeer=1`.
  - RX/TX counters increased after commands (`rx`, `txA`, `txOk`).
- Peer table usage is functioning on `/dev/ttyUSB1`:
  - One peer is tracked (`peer[0]=F4:65:0B:D8:57:DC`).

## Not Confirmed / Failing in This Evidence (`src/main.cpp`)

- Full bidirectional serial-command responsiveness is **not confirmed**:
  - `/dev/ttyUSB6` showed `(no output)` for every scripted command (`0`, `z`, `i`, `b`, `r`, `f`, `s`, `k`, `w`).
- Node-2 command path in `handleDebugSerial()` is therefore **not validated** by this log.
- Start transition behavior from lobby is **not validated** by this specific run:
  - Node 1 was already in `IN_GAME` at first snapshot.
  - No `LOBBY -> STARTING -> IN_GAME` transition appears in the captured session.
- Local reset command path (`d`) is **not validated** in this run:
  - This short run did not include post-reset output in the attached log.

## Confirmed Working (Overall Project)

- Build/flash + serial automation pipeline works sufficiently to execute scripted tests:
  - Scripted command injection succeeded on at least one board.
  - Session logging to `scripts/serial_test_session.log` works.
- Two-device network presence is at least partially working:
  - Node 1 sees one peer and exchanges packets while receiving command-driven traffic.

## Not Confirmed / Open Issues (Overall Project)

- Symmetric two-node runtime behavior is **not confirmed** from this log:
  - One board appears non-responsive over serial during the session.
- End-to-end two-node gameplay flow in this particular run is **not demonstrated** (because initial state was already `IN_GAME` on node 1 and node 2 output was silent).
- Hardware-dependent systems (IR hit path, OLED verification, buzzer/motor correctness) remain unverified in this evidence.

## Recommended Next Verification Pass

- Force both nodes to a known baseline (`LOBBY`) before testing (power-cycle or reset command with visible confirmation on both).
- Capture independent live monitors for both ports while running the smoke script.
- Re-run and verify these checkpoints are present in both logs:
  - command echo for `0/z/i/a|b/r/s/k/w`
  - `LOBBY -> STARTING -> IN_GAME`
  - non-zero RX/TX counters on both nodes
  - consistent peer visibility (`peers=1`) on both nodes

