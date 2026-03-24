# ESP32 Laser Tag Node — Full Code Reference

> **File:** `laser_tag_node.ino` · **Lines:** 1,255 · **Target:** ESP32 Dev Module (arduino-esp32 v3.3.5)

This document walks through every section of the node firmware from top to bottom. The same binary is flashed to all four units; each one discovers its own player ID at runtime by comparing MAC addresses.

---

## Table of Contents

1. [Includes](#1-includes)
2. [Pin Definitions](#2-pin-definitions)
3. [Constants](#3-constants)
4. [Enumerations](#4-enumerations)
5. [Data Structures](#5-data-structures)
6. [Global State](#6-global-state)
7. [Utility — CRC32 / HMAC](#7-utility--crc32--hmac)
8. [Utility — Nonce Log](#8-utility--nonce-log)
9. [Utility — ESP32 RNG](#9-utility--esp32-rng)
10. [Hardware — IR Transmitter](#10-hardware--ir-transmitter)
11. [Hardware — IR Receiver](#11-hardware--ir-receiver)
12. [Hardware — Buzzer](#12-hardware--buzzer)
13. [Hardware — Vibration Motor](#13-hardware--vibration-motor)
14. [Hardware — WS2812B LEDs](#14-hardware--ws2812b-leds)
15. [OLED Display](#15-oled-display)
16. [Game Table](#16-game-table)
17. [Player ID Assignment](#17-player-id-assignment)
18. [ECDH Key Exchange](#18-ecdh-key-exchange)
19. [ESP-NOW Send Helpers](#19-esp-now-send-helpers)
20. [Pending Hit Confirmation](#20-pending-hit-confirmation)
21. [IR Hit Processing](#21-ir-hit-processing)
22. [Win Condition](#22-win-condition)
23. [Reset](#23-reset)
24. [ESP-NOW Receive Callback](#24-esp-now-receive-callback)
25. [ESP-NOW Init](#25-esp-now-init)
26. [Button Handling](#26-button-handling)
27. [Weapon Mode](#27-weapon-mode)
28. [Silent Mode Expiry](#28-silent-mode-expiry)
29. [Game Starting Countdown](#29-game-starting-countdown)
30. [Lobby Broadcast](#30-lobby-broadcast)
31. [Periodic Sync](#31-periodic-sync)
32. [IR Receive Check](#32-ir-receive-check)
33. [setup()](#33-setup)
34. [loop()](#34-loop)

---

## 1. Includes

```cpp
#include <Arduino.h>
#include <esp_now.h>
#include <WiFi.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <FastLED.h>
#include <IRremoteESP8266.h>
#include <IRsend.h>
#include <IRrecv.h>
#include <IRutils.h>
#include <uECC.h>
#include <algorithm>
#include <string.h>
#include <stdint.h>
```

**Lines 15–29.** These headers pull in everything the firmware depends on:

| Header | Purpose |
|--------|---------|
| `Arduino.h` | Core Arduino API (`pinMode`, `millis`, `delay`, etc.) |
| `esp_now.h` | Espressif's peer-to-peer Wi-Fi protocol used for game state packets |
| `WiFi.h` | Required to initialise the radio before ESP-NOW can use it |
| `Wire.h` | I2C bus driver — used by the OLED display |
| `Adafruit_GFX.h` | Graphics primitives (text, shapes) — base library for SSD1306 |
| `Adafruit_SSD1306.h` | Driver for the 128×64 OLED display |
| `FastLED.h` | High-performance WS2812B LED control |
| `IRremoteESP8266.h` / `IRsend.h` / `IRrecv.h` / `IRutils.h` | IR transmit and receive at 38 kHz |
| `uECC.h` | Micro elliptic-curve cryptography — ECDH key exchange on constrained hardware |
| `algorithm`, `string.h`, `stdint.h` | Standard C++ utilities, `memcpy`/`memset`, fixed-width integer types |

---

## 2. Pin Definitions

```cpp
#define PIN_IR_FRONT        34
#define PIN_IR_BACK         35
#define PIN_IR_LEFT         32
#define PIN_IR_RIGHT        33
#define PIN_IR_GUN          25
#define PIN_IR_TX           26
#define PIN_WS2812B         27
#define PIN_BUZZER          14
#define PIN_MOTOR           12
#define PIN_BTN_RELOAD      13
#define PIN_BTN_TEAM        4
#define PIN_BTN_SILENT      5
#define PIN_BTN_RESET_VOTE  18
#define PIN_POT             36

#define OLED_SDA            21
#define OLED_SCL            22
#define OLED_WIDTH          128
#define OLED_HEIGHT         64
#define OLED_ADDR           0x3C
```

**Lines 34–53.** Every GPIO assignment lives here so that changing your wiring means editing one block, not hunting through the code.

- **IR receivers (34, 35, 32, 33, 25):** The TSOP38238 output is active-low — it pulls its signal pin to GND when IR at 38 kHz is detected. Pins 34/35/36 are input-only ADC pins on most ESP32 variants; they work fine for digital reads here.
- **PIN_IR_TX (26):** The base of a 2N2222 NPN transistor. The ESP32 GPIO drives the transistor, and the transistor drives the IR LED at proper current. Never connect a high-power IR LED directly to a GPIO.
- **PIN_WS2812B (27):** Single data line for the entire LED chain (gun LEDs + vest LEDs + sensor housing LEDs).
- **PIN_BUZZER (14):** Passive buzzer driven by `tone()` / PWM. Must be passive — active buzzers only produce one frequency.
- **PIN_MOTOR (12):** Vibration motor driven through a transistor (coin motor draws more current than a GPIO can safely supply).
- **PIN_POT (36):** Potentiometer wiper feeding an ADC input. Read with `analogRead()` to select weapon mode.
- **OLED (SDA=21, SCL=22):** Standard I2C pins on most ESP32 DevKit boards.

---

## 3. Constants

```cpp
#define MAX_PLAYERS         4
#define STARTING_HP         20
#define NUM_LEDS            8
#define IR_FREQ_KHZ         38
#define IR_PACKET_BITS      32
#define NONCE_LOG_SIZE      32
#define PENDING_EXPIRE_MS   2000
#define HIT_CLAIM_RETRIES   3
#define HIT_CLAIM_GAP_MS    50
#define SILENT_MODE_MS      120000UL
#define SYNC_INTERVAL_MS    30000UL
#define LOBBY_BCAST_MS      500UL
#define AR_AMMO_MAX         30
#define AR_COOLDOWN_MS      150
#define PISTOL_COOLDOWN_MS  300
#define MOTOR_HIT_MS        100
#define MOTOR_KILL_MS       150
#define MOTOR_DEATH_MS      500
#define MOTOR_WIN_MS        120
```

**Lines 58–76.** All timing, size, and game-rule constants in one place so that tuning gameplay (HP, ammo, cooldowns) doesn't require searching through logic code.

| Constant | Value | Meaning |
|----------|-------|---------|
| `MAX_PLAYERS` | 4 | Maximum simultaneous players; drives array sizes |
| `STARTING_HP` | 20 | HP each player starts a round with |
| `NUM_LEDS` | 8 | Adjust to match the actual number of WS2812B LEDs chained on your unit |
| `IR_PACKET_BITS` | 32 | Total bits in one IR transmission |
| `NONCE_LOG_SIZE` | 32 | Circular buffer capacity for replay-prevention nonce tracking |
| `PENDING_EXPIRE_MS` | 2000 | ms before an unmatched HIT_CLAIM or SHOT_CONFIRM is discarded |
| `HIT_CLAIM_RETRIES` | 3 | How many times the victim retransmits a HIT_CLAIM |
| `HIT_CLAIM_GAP_MS` | 50 | ms between HIT_CLAIM retransmissions |
| `SILENT_MODE_MS` | 120000 | 2 minutes in milliseconds |
| `SYNC_INTERVAL_MS` | 30000 | Periodic game-table sync every 30 seconds |
| `LOBBY_BCAST_MS` | 500 | Lobby beacon rate — broadcast public key and team every 500ms |
| `AR_AMMO_MAX` | 30 | Full magazine for the AR weapon |
| `AR_COOLDOWN_MS` | 150 | Minimum ms between AR shots |
| `PISTOL_COOLDOWN_MS` | 300 | Minimum ms between Pistol shots |
| `MOTOR_*_MS` | various | Vibration pulse lengths for different game events |

---

## 4. Enumerations

```cpp
enum GameState { LOBBY, STARTING, IN_GAME, ROUND_OVER, RESETTING };
enum WeaponMode { PISTOL, AR };
enum Team { TEAM_NONE = 0, TEAM_RED, TEAM_BLUE, TEAM_GREEN, TEAM_YELLOW };
enum PacketType : uint8_t {
    PKT_PUBKEY_BROADCAST = 1,
    PKT_TEAM_SELECT,
    PKT_READY_VOTE,
    PKT_HIT_CLAIM,
    PKT_SHOT_CONFIRM,
    PKT_SYNC_REQUEST,
    PKT_SYNC_RESPONSE,
    PKT_RESET_VOTE
};
```

**Lines 81–93.**

**`GameState`** drives the main `loop()` `switch` statement:
- `LOBBY` — players pick teams, ECDH key exchange runs, ready votes collected
- `STARTING` — countdown animation plays, then transitions to `IN_GAME`
- `IN_GAME` — active play; IR and ESP-NOW both running
- `ROUND_OVER` — last team standing detected; waiting for reset votes
- `RESETTING` — all reset votes received; clears state and returns to `LOBBY`

**`WeaponMode`** controls fire rate and damage. The potentiometer selects between the two at the moment of firing.

**`Team`** — `TEAM_NONE` is the unassigned default in lobby. Values 1–4 map to the four team colours.

**`PacketType`** — stored in every ESP-NOW packet header. Starting at `1` (not `0`) means a zero-initialised buffer will never accidentally match a valid packet type. The `: uint8_t` suffix ensures the enum is packed as a single byte on the wire.

---

## 5. Data Structures

### `Slot` (lines 99–103)
```cpp
struct Slot {
    uint8_t  ownerID;
    int32_t  value;     // HP
    uint32_t version;
};
```
One slot per player in the distributed game state table. `version` is a monotonically increasing counter used to resolve conflicts when merging tables from multiple nodes. The merge rules are: highest version wins; version tie goes to lowest HP; HP can never increase.

### `PktHeader` (lines 106–109)
```cpp
struct PktHeader {
    PacketType type;
    uint8_t    senderID;
};
```
Prepended to every ESP-NOW packet. `onDataRecv` reads just this header first to dispatch to the correct handler without casting the full buffer.

### Packet structs (lines 112–171)

| Struct | Fields beyond header | Purpose |
|--------|---------------------|---------|
| `PktPubKey` | `pubKey[64]` | Broadcasts the uncompressed secp256r1 public key (64 bytes) during lobby |
| `PktTeamSelect` | `team` | Announces which team colour this player has chosen |
| `PktVote` | *(none)* | Dual-purpose: used for both READY_VOTE and RESET_VOTE — only the `type` field differs |
| `PktHitClaim` | `victimID`, `shooterID`, `nonce`, `delta`, `newHP`, `version`, `hmac` | Victim's declaration that they were hit; contains full damage details and HMAC signature |
| `PktShotConfirm` | `shooterID`, `nonce`, `hmac` | Shooter's corroboration that they actually fired the matching nonce |
| `PktSyncRequest` | *(none)* | Asks all peers to send their full game table |
| `PktSyncResponse` | `table[MAX_PLAYERS]` | Full game table snapshot sent in reply to a sync request |

### `PendingEntry` (lines 160–171)
```cpp
struct PendingEntry {
    bool     active;
    uint32_t nonce;
    uint8_t  victimID;
    uint8_t  shooterID;
    int32_t  delta;
    int32_t  newHP;
    uint32_t version;
    bool     claimSeen;
    bool     confirmSeen;
    uint32_t expiresAt;
};
```
Holds an unresolved hit while the firmware waits for both `HIT_CLAIM` and `SHOT_CONFIRM` to arrive. A hit is only committed to the game table when both `claimSeen` and `confirmSeen` are true. If they don't both arrive within `PENDING_EXPIRE_MS` (2 seconds), `active` is set to false and the entry is silently discarded.

---

## 6. Global State

**Lines 177–229.** All runtime state is in global variables — standard practice for Arduino firmware where the stack is small and there's no OS or heap manager.

### Hardware objects (lines 178–181)
```cpp
Adafruit_SSD1306 oled(OLED_WIDTH, OLED_HEIGHT, &Wire, -1);
IRsend           irSend(PIN_IR_TX);
IRrecv           irRecv(PIN_IR_FRONT);
CRGB             leds[NUM_LEDS];
```
- `oled` — OLED display instance; `-1` means no hardware reset pin
- `irSend` — configured to drive `PIN_IR_TX`
- `irRecv` — listens on the front receiver (primary decode channel)
- `leds[]` — FastLED pixel buffer; written to by LED functions, pushed to hardware by `FastLED.show()`

### Networking (lines 184–186)
- `myMAC[6]` — this unit's own MAC address, read at startup with `WiFi.macAddress()`
- `peerMACs[][6]` — MACs of other nodes, discovered during lobby key exchange
- `peerCount` — number of peers seen so far

### Game state (lines 189–199)
- `gameState` — current state machine position
- `myPlayerID` — initialised to `0xFF` (unassigned); set by `assignPlayerIDs()` once all players are in lobby
- `myTeam` / `peerTeams[]` — team colours for this node and all peers
- `peerReady[]` / `peerResetVote[]` — ready and reset vote tracking per player
- `gameTable[]` — the distributed HP table (one `Slot` per player)
- `weaponMode` / `arAmmo` — current weapon and AR ammo count
- `silentMode` / `silentStart` — silent mode toggle and start timestamp

### Hit tracking (lines 202–204)
- `usedNonces[]` — circular buffer of 32 nonces; checked before processing any hit to prevent replay attacks
- `nonceHead` — write index into the circular buffer
- `pending[]` — up to 8 pending hit entries awaiting two-factor confirmation

### ECDH keys (lines 207–211)
- `privateKey[32]` — ephemeral private key, **never leaves RAM**
- `publicKey[64]` — uncompressed secp256r1 public key broadcast to peers
- `sharedSecrets[][32]` — derived per-peer shared secrets used to key the HMAC
- `peerPubKeys[][64]` — collected public keys from peers
- `pubKeyReceived[]` — flag per peer: have we received their public key yet?

### Timers (lines 214–229)
- `lastSync` / `lastLobbyBcast` / `lastFire` — timestamps for rate-limiting periodic actions
- `silentEnd` — absolute `millis()` value when silent mode expires
- `reloadPending` / `reloadStart` — tracks the 2-second reload delay
- `btnXxxLast` — one debounce timestamp per button (80ms debounce window)
- `displayDirty` — flag; set whenever state changes so `displayUpdate()` redraws only when needed

---

## 7. Utility — CRC32 / HMAC

```cpp
uint32_t crc32(const uint8_t *data, size_t len) { ... }

uint32_t computeHMAC(uint8_t senderID, int32_t delta, int32_t newHP,
                     uint32_t version, const uint8_t *sharedSecret) { ... }

bool verifyHMAC(...) { ... }
```

**Lines 241–267.**

### `crc32`
A standard software CRC32 using the Ethernet polynomial (`0xEDB88320`). Initialises to `0xFFFFFFFF`, XORs each byte, runs 8 shift-and-XOR rounds, then inverts the result. This is the IEEE 802.3 CRC used in Ethernet frames — well-studied, collision resistant for this use case.

### `computeHMAC`
Builds a 16-byte buffer containing:
- 1 byte: `senderID`
- 4 bytes: `delta` (damage, negative)
- 4 bytes: `newHP`
- 4 bytes: `version`
- 4 bytes: first 4 bytes of the pairwise ECDH shared secret (the keying material)

Then runs CRC32 over that buffer to produce a 32-bit authentication tag. This is a keyed CRC rather than a true HMAC-SHA256, which is appropriate for the threat model (casual cheating, not cryptographic adversaries). The comment in the code notes that SHA256-HMAC with the ESP32 hardware accelerator would be a drop-in upgrade.

### `verifyHMAC`
Returns `true` if the recomputed HMAC matches the received one. If `sharedSecret` is `nullptr` (Phase 1 or 2, before authentication is enabled), verification is skipped and the function always returns `true` — so the same code path works across all phases.

---

## 8. Utility — Nonce Log

```cpp
bool nonceUsed(uint32_t nonce) { ... }
void recordNonce(uint32_t nonce) { ... }
```

**Lines 272–281.** A circular buffer of 32 `uint32_t` values.

`nonceUsed` does a linear scan across all 32 slots. With only 4 players, 32 entries gives ample replay protection — a fired nonce is rejected for as long as it stays in the ring, which is until 32 more shots have been fired.

`recordNonce` writes the nonce at `nonceHead` and advances the index modulo `NONCE_LOG_SIZE`. When the ring is full, the oldest nonce is silently overwritten.

The same buffer serves a dual purpose: nonces recorded when we *fire* are checked against incoming `HIT_CLAIM` packets to confirm we actually shot that nonce; nonces recorded when we *commit* a hit are checked against future packets to prevent replaying a confirmed hit.

---

## 9. Utility — ESP32 RNG

```cpp
static int esp32RNG(uint8_t *dest, unsigned size) {
    for (unsigned i = 0; i < size; i++)
        dest[i] = (uint8_t)esp_random();
    return 1;
}
```

**Lines 286–290.** A callback adapter for the uECC library. uECC requires a pointer to a function with this exact signature that fills a buffer with random bytes. `esp_random()` uses the ESP32's hardware random number generator, seeded from thermal and radio noise — appropriate for cryptographic key generation.

---

## 10. Hardware — IR Transmitter

### `buildIRPacket` (lines 296–304)
```cpp
uint32_t buildIRPacket(uint8_t shooterID, uint32_t nonce, uint8_t damage)
```
Packs the 32-bit IR payload:

```
Bits 31–28 : shooterID  (4 bits, player 0–15)
Bits 27–6  : nonce      (22 bits, ~4 million values)
Bits 5–2   : damage     (4 bits, weapon damage value)
Bits 1–0   : checksum   (2 bits, XOR of all above)
```

The checksum is computed by XOR-folding all fields down to 2 bits: `(shooterID ^ (nonce>>14) ^ (nonce>>7) ^ nonce ^ damage) & 0x03`. A corrupt packet received with a wrong checksum is discarded by `parseIRPacket`.

### `parseIRPacket` (lines 306–314)
The inverse of `buildIRPacket`. Extracts each field by masking and shifting, recomputes the checksum, and returns `false` if there's a mismatch. Silent discard of bad packets prevents ambient IR noise from registering as hits.

### `fireGun` (lines 316–340)
```cpp
void fireGun()
```
The complete firing sequence:
1. Checks the cooldown timer (`lastFire`) — returns immediately if firing too fast
2. Checks AR ammo — returns if empty
3. Checks `myPlayerID != 0xFF` — prevents firing before player ID is assigned in lobby
4. Records the fire timestamp
5. Determines damage from weapon mode (Pistol = 2, AR = 4)
6. Generates a 22-bit random nonce with `esp_random()`
7. Calls `buildIRPacket` and transmits via `irSend.sendNEC()` at NEC protocol timing
8. Decrements AR ammo
9. Records the nonce in `usedNonces` — this is how we later recognise a matching `HIT_CLAIM`

The gun trigger GPIO is deliberately not wired in this file. Connect it to an interrupt or poll it in the loop and call `fireGun()`.

---

## 11. Hardware — IR Receiver

```cpp
bool hitDetected() {
    return !digitalRead(PIN_IR_FRONT) ||
           !digitalRead(PIN_IR_BACK)  ||
           !digitalRead(PIN_IR_LEFT)  ||
           !digitalRead(PIN_IR_RIGHT) ||
           !digitalRead(PIN_IR_GUN);
}
```

**Lines 345–351.** Polls all five TSOP38238 receivers. Because the TSOP output is active-low (HIGH at rest, pulls LOW when receiving 38 kHz IR), the reading is inverted with `!`. Any single receiver going low constitutes a hit.

Full packet decoding runs through the IRremoteESP8266 library on `PIN_IR_FRONT` only (the primary receiver). In `checkIRReceive`, if the library decodes a valid 32-bit packet, that packet is processed. The secondary receivers (`hitDetected()`) serve as physical detection confirmation — a full multi-pin decode implementation would run the software decoder on all five pins.

---

## 12. Hardware — Buzzer

**Lines 356–370.**

```cpp
void beep(uint16_t freq, uint16_t durationMs)
```
Calls Arduino's `tone()` to generate PWM at the given frequency, waits, then calls `noTone()`. The 10ms padding after `durationMs` prevents the next tone from starting before the previous one fully stops. **Silent mode check first** — `beep()` returns immediately if `silentMode` is true.

The tune functions each call `beep()` with a sequence of notes:

| Function | Notes | Effect |
|----------|-------|--------|
| `playTuneHit` | *(silent)* | No sound on hit, per spec |
| `playTuneDeath` | 600→400→200 Hz | Descending tone |
| `playTuneWin` | 500→700→900 Hz | Ascending victory tone |
| `playTuneLose` | 400→250 Hz | Downward tone |
| `playTuneStart` | 600→700→800→1000 Hz | Rising game-start fanfare |
| `playSilentOn` | 700→500 Hz | Descending two-note (plays *before* going silent) |
| `playSilentOff` | 500→700 Hz | Ascending two-note on restore |
| `playCountdownBeep` | 800 or 1200 Hz | Lower pitch per second; higher pitch on "GO" |

`playSilentOn` and `playSilentOff` deliberately bypass the `silentMode` guard (they play directly via `tone()`) because they play at the moment of toggling, not during silent mode.

---

## 13. Hardware — Vibration Motor

**Lines 375–385.**

```cpp
void motorPulse(uint32_t ms) {
    digitalWrite(PIN_MOTOR, HIGH);
    delay(ms);
    digitalWrite(PIN_MOTOR, LOW);
}
```

Sets the motor driver GPIO high, waits `ms` milliseconds, then pulls it low. The motor is driven through a transistor; the GPIO only controls the base.

| Wrapper | Pattern | Duration |
|---------|---------|----------|
| `vibrateHit` | Single pulse | 100ms |
| `vibrateKill` | Two pulses | 150ms + 60ms gap + 150ms |
| `vibrateDeath` | Single long pulse | 500ms |
| `vibrateWin` | Three pulses | 120ms × 3, 60ms gaps |
| `vibrateSilent` | Two pulses | 80ms + 60ms gap + 80ms |

---

## 14. Hardware — WS2812B LEDs

**Lines 390–450.**

### `teamColor` (lines 390–398)
Returns a `CRGB` colour for each team enum value. Yellow is set to `CRGB(255,200,0)` rather than full yellow to avoid looking white outdoors.

### `setAllLEDs` / `ledsOff` / `flashLEDs`
Low-level helpers. `fill_solid` fills the buffer; `FastLED.show()` pushes it to the hardware. `flashLEDs` sets a colour, waits, then goes black.

### `ledHitFlash` (lines 413–418)
Saves the current team colour, flashes white for 80ms, then restores. Suppressed in silent mode.

### `ledCryptoEviction` (lines 420–427)
Flashes all LEDs red rapidly 8 times (8 × 160ms = ~1.3 seconds). Called when a rebooted node's packets are rejected — indicates to the player and bystanders that authentication has failed.

### `updateLEDs` (lines 429–450)
The main LED state machine, called every loop iteration:
- **Silent mode:** all LEDs off
- **LOBBY + no team:** slow sine-wave white pulse using `sin(millis() / 800.0)`
- **LOBBY + team selected:** solid team colour
- **IN_GAME + alive:** solid team colour
- **IN_GAME + dead:** all off (handled by `me.value <= 0` check)
- **ROUND_OVER:** single-LED chase animation — one LED lit at `(millis()/100) % NUM_LEDS`, cycling through the chain

---

## 15. OLED Display

**Lines 455–519.**

### `displayUpdate` (lines 455–508)
Only redraws when `displayDirty` is true — avoids I2C traffic every 10ms loop iteration. Clears the display, then renders one of several layouts:

**LOBBY layout:**
```
ID:0  Team: RED
--- Lobby ---
P0: RED  (RDY)
P1: BLUE
P2: GRN  (RDY)
P3: NONE
```

**IN_GAME layout:**
```
HP:16/20
AR  Ammo:24/30
Alive:3
```
If the player is dead, a large `DEAD` overlays the bottom half. If `ROUND_OVER`, a large `YOU WIN!` or `YOU LOSE` appears. If silent mode is active, a countdown `SILENT 87s` appears at the bottom.

### `flashKill` (lines 510–519)
Immediately overrides the display with a large `KILL!` message for 1 second, then sets `displayDirty = true` to redraw the normal game view. Called when this node's confirmed shot kills an opponent.

---

## 16. Game Table

**Lines 524–550.**

### `initTable`
Sets all four `Slot` entries to `ownerID = i`, `value = STARTING_HP (20)`, `version = 0`. Called at startup and on reset.

### `mergeSlot`
Applies the conflict-resolution rules when receiving table data from a peer:
1. **HP can never increase** — if `remote.value > local.value`, reject
2. **Highest version wins** — if `remote.version > local.version`, accept
3. **Version tie → lowest HP wins** — if versions are equal and `remote.value < local.value`, accept

This ensures that a rebooted node (version 0) cannot override legitimate state held by other nodes (higher versions), and that nobody can broadcast a fake HP increase.

### `mergeTable`
Loops over all four slots from a `PktSyncResponse` and calls `mergeSlot` on each.

---

## 17. Player ID Assignment

```cpp
void assignPlayerIDs()
```

**Lines 556–582.** Deterministic, coordination-free player ID assignment. Algorithm:

1. Build an array of all known MACs (own MAC + all peer MACs collected during lobby)
2. Bubble-sort the array in ascending byte order
3. Find own MAC in the sorted array — that index becomes `myPlayerID`

Because every node runs the same sort on the same MAC set, they all independently arrive at the same mapping. The same physical device always gets the same player ID when playing with the same group.

---

## 18. ECDH Key Exchange

**Lines 587–598.**

### `generateKeyPair`
```cpp
uECC_set_rng(esp32RNG);
uECC_make_key(publicKey, privateKey, uECC_secp256r1());
```
Registers the hardware RNG callback, then generates a secp256r1 keypair. Called at boot and at every round reset. The private key lives only in RAM — a power cycle destroys it, which is the intended "cryptographic eviction" behaviour.

### `deriveSharedSecrets`
```cpp
uECC_shared_secret(peerPubKeys[i], privateKey, sharedSecrets[i], uECC_secp256r1());
```
For each peer whose public key has been received, computes the ECDH shared secret: `private_key × peer_public_key`. Because of the mathematics of elliptic curve Diffie-Hellman, both parties compute the same value without ever transmitting it. The shared secret is stored in `sharedSecrets[i]` and used to key the HMAC on all subsequent packets to/from that peer.

---

## 19. ESP-NOW Send Helpers

**Lines 603–673.** A thin wrapper layer that constructs each packet struct, fills the header, and calls `esp_now_send`. All broadcast packets go to `BROADCAST_MAC` (`FF:FF:FF:FF:FF:FF`). Only `sendSyncResponse` is unicast, using the MAC from the sync request's source address.

| Function | Packet type | Notes |
|----------|------------|-------|
| `espNowSend` | *(wrapper)* | Calls `esp_now_send` to broadcast |
| `sendPubKey` | `PKT_PUBKEY_BROADCAST` | Copies `publicKey[64]` into payload |
| `sendTeamSelect` | `PKT_TEAM_SELECT` | Sends `myTeam` |
| `sendReadyVote` | `PKT_READY_VOTE` | Header only |
| `sendResetVote` | `PKT_RESET_VOTE` | Header only |
| `sendSyncRequest` | `PKT_SYNC_REQUEST` | Header only |
| `sendSyncResponse` | `PKT_SYNC_RESPONSE` | Unicast; copies full `gameTable[]` |
| `sendHitClaim` | `PKT_HIT_CLAIM` | Computes HMAC; retransmits 3× with 50ms gap |
| `sendShotConfirm` | `PKT_SHOT_CONFIRM` | Computes HMAC; sent once |

`sendHitClaim` retransmits three times with 50ms spacing to maximise the chance the shooter receives it, especially at the edges of ESP-NOW range. The used-nonce log on all nodes ensures duplicate claims don't result in double damage.

---

## 20. Pending Hit Confirmation

**Lines 678–765.** The two-factor hit confirmation engine — the core anti-cheat mechanism.

### `findPending` (lines 678–682)
Linear scan through the 8-slot pending array looking for an active entry with a matching nonce. Returns a pointer or `nullptr`.

### `allocPending` (lines 684–689)
Finds an inactive slot to write a new entry into. If all 8 slots are active (shouldn't happen in a 4-player game), evicts slot 0 (oldest by position).

### `expirePending` (lines 691–695)
Called every loop iteration. Marks any active entry older than `PENDING_EXPIRE_MS` (2 seconds) as inactive. This is what prevents a fake hit claim (no matching confirm ever arrives) from hanging around forever.

### `tryCommitPending` (lines 697–729)
The commit gate — only runs when both `claimSeen` and `confirmSeen` are true. Applies all validation checks in order:

1. `delta >= 0` → reject (HP can only decrease)
2. `version != slot.version + 1` → reject (must be exactly the next version)
3. `slot.value + delta != newHP` → reject (arithmetic must check out)
4. `nonceUsed(nonce)` → reject (replay prevention)

If all checks pass, the hit is committed: `slot.value` and `slot.version` are updated, the nonce is recorded, and the entry is cleared.

Post-commit effects:
- If this player was killed (`victimID == myPlayerID && value <= 0`): long vibration, death tune, LEDs off
- If this node fired the killing shot (`shooterID == myPlayerID`): double vibration, 1-second `KILL!` display
- Always: call `checkWinCondition()`

### `addHitClaim` (lines 731–752)
Receives a `PktHitClaim`. Creates or finds the pending entry for this nonce, verifies the HMAC, sets `claimSeen = true`, and calls `tryCommitPending`. If HMAC fails, the function returns without setting the flag — the claim is silently dropped.

### `addShotConfirm` (lines 754–766)
Receives a `PktShotConfirm`. Creates or finds the pending entry for this nonce, sets `confirmSeen = true`, and calls `tryCommitPending`.

Note that a `SHOT_CONFIRM` can arrive before the `HIT_CLAIM` (network ordering is not guaranteed). The pending system handles this gracefully — whichever half arrives first creates the entry; the second half completes it.

---

## 21. IR Hit Processing

```cpp
void processIRHit(uint32_t raw)
```

**Lines 771–798.** Called when the IR receive library decodes a 32-bit packet.

Guard conditions checked first:
- Not `IN_GAME` → ignore
- `myPlayerID >= MAX_PLAYERS` → not yet assigned → ignore
- Already dead → ignore (dead players don't take hits)
- Checksum fails (`parseIRPacket` returns false) → ignore
- Shooter is this player → ignore (self-shot)
- Friendly fire: `peerTeams[shooterID] == myTeam` → silently ignore

If all guards pass:
1. Compute `delta = -(int32_t)damage` and `newHP = max(0, curHP + delta)`
2. Increment version
3. Trigger vibration and LED hit flash (immediate local feedback)
4. Set `displayDirty`
5. Call `sendHitClaim` (3 retransmissions)

The local HP is **not** updated here — it only changes when `tryCommitPending` runs successfully. This prevents a scenario where the victim updates their own HP but the shooter's `SHOT_CONFIRM` never arrives, leaving the HP in a state the other nodes don't agree on.

---

## 22. Win Condition

```cpp
void checkWinCondition()
```

**Lines 804–832.** Called after every successful HP commit.

Logic:
1. Count all players with `HP > 0` (`livingCount`)
2. Check if all living players share the same `teamID` (`multiTeam = false`)
3. Win condition: `livingCount == 0` (everyone died simultaneously) OR `!multiTeam` (one team remains)

On win:
- Set `gameState = ROUND_OVER`
- If this node is alive → `playTuneWin()` + `vibrateWin()`
- If this node is dead → `playTuneLose()`

This handles all configurations: 1v1v1v1, 2v2, 1v3, and even a simultaneous-death draw.

---

## 23. Reset

```cpp
void doReset()
```

**Lines 837–849.** Full round reset triggered when all players have voted:

1. `initTable()` — restore all HP to 20, versions to 0
2. Clear `usedNonces`, `nonceHead`, `pending[]` — wipe hit state
3. Clear `peerReady[]`, `peerResetVote[]` — ready for the next ready/reset cycle
4. Restore `arAmmo` to full
5. Clear `silentMode`
6. `generateKeyPair()` — fresh ECDH keypair for the new round. This is critical: any node that rebooted during the previous round had its keys wiped. The new round gives everyone a fresh start on equal footing, with new session keys.
7. Return to `LOBBY`

---

## 24. ESP-NOW Receive Callback

```cpp
void onDataRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len)
```

**Lines 854–955.** The v3.x receive callback signature. All incoming ESP-NOW data arrives here, regardless of source.

First validates that the payload is at least as large as a `PktHeader`, casts the first two bytes, and dispatches on `hdr->type`:

### `PKT_PUBKEY_BROADCAST`
- Ignored outside `LOBBY` (key exchange locks at game start)
- Saves the 64-byte public key to `peerPubKeys[sid]`
- Registers the sender's MAC in `peerMACs[]` for later unicast use

### `PKT_TEAM_SELECT`
- Updates `peerTeams[sid]` and sets `displayDirty`

### `PKT_READY_VOTE`
- Sets `peerReady[sid]`
- Checks for unanimous readiness across all four players
- On unanimous ready: derives shared secrets, assigns player IDs, initialises own HP slot, transitions to `STARTING`

### `PKT_HIT_CLAIM`
- If `shooterID == myPlayerID`: sends `SHOT_CONFIRM` (this node is being claimed as the shooter)
- Calls `addHitClaim` to register the claim in the pending system

### `PKT_SHOT_CONFIRM`
- Calls `addShotConfirm` to register in the pending system

### `PKT_SYNC_REQUEST`
- Responds with a unicast `SYNC_RESPONSE` to the requester's MAC

### `PKT_SYNC_RESPONSE`
- Calls `mergeTable` to integrate the received state using the conflict-resolution rules

### `PKT_RESET_VOTE`
- Sets `peerResetVote[sid]`
- Checks for unanimous votes across all four players (including dead players)
- On unanimous vote: calls `doReset()`

---

## 25. ESP-NOW Init

```cpp
void initEspNow()
```

**Lines 967–984.**

1. `WiFi.mode(WIFI_STA)` — required to initialise the radio; ESP-NOW runs on top of the Wi-Fi MAC layer
2. `WiFi.disconnect()` — ensures no AP association, which would conflict with ESP-NOW channel usage
3. `esp_now_init()` — initialises the ESP-NOW stack
4. Registers `onDataRecv` and `onDataSent` callbacks
5. Adds the broadcast MAC (`FF:FF:FF:FF:FF:FF`) as a peer — **required** in v3.x before any broadcast can be sent. Without this, `esp_now_send` to the broadcast address returns an error.
6. Uses `memset(&peerInfo, 0, sizeof(peerInfo))` before filling the struct — a v3.x requirement; unzeroed peer structs can cause subtle failures.

---

## 26. Button Handling

```cpp
bool btnPressed(uint8_t pin, uint32_t &lastTime)
void handleButtons()
```

**Lines 989–1045.**

### `btnPressed`
Software debounce: returns `true` only if the pin is `LOW` (active-low with `INPUT_PULLUP`) AND at least `BTN_DEBOUNCE_MS` (80ms) has elapsed since the last registered press. Updates `lastTime` on each accepted press.

### `handleButtons`

**Reload button (`PIN_BTN_RELOAD`):**
- In AR mode: starts a 2-second reload timer (`reloadPending = true`)
- When timer expires: restores `arAmmo` to `AR_AMMO_MAX`
- The 2-second delay is tracked by comparing `millis() - reloadStart >= 2000` every loop iteration

**Team cycle button (`PIN_BTN_TEAM`):**
- Only active in `LOBBY` state
- Increments `myTeam` modulo 4, cycling through RED → BLUE → GREEN → YELLOW → RED
- Broadcasts the new selection with `sendTeamSelect()`
- Updates LEDs immediately to show the new colour

**Silent mode button (`PIN_BTN_SILENT`):**
- Toggles silent mode on/off
- On activate: sets `silentEnd = millis() + SILENT_MODE_MS`, plays descending tone, double vibration
- On deactivate: plays ascending tone, double vibration
- Calls `updateLEDs()` to immediately extinguish or restore LEDs

**Reset vote button (`PIN_BTN_RESET_VOTE`):**
- Records this player's own vote in `peerResetVote[myPlayerID]`
- Broadcasts `PKT_RESET_VOTE` to all peers

---

## 27. Weapon Mode

```cpp
void updateWeaponMode()
```

**Lines 1050–1058.** Reads the potentiometer ADC on `PIN_POT` (0–4095 on the ESP32's 12-bit ADC). Values above 2048 (roughly centre) select AR; below select Pistol. On mode change, resets `arAmmo` to full (switching to AR gives a fresh magazine) and sets `displayDirty`.

---

## 28. Silent Mode Expiry

```cpp
void checkSilentExpiry()
```

**Lines 1063–1071.** Checks every loop iteration whether silent mode has run for its full 2 minutes. On expiry: clears `silentMode`, plays the ascending restore tone, double vibration, calls `updateLEDs()` to restore LEDs to team colour.

---

## 29. Game Starting Countdown

```cpp
void runStartingCountdown()
```

**Lines 1076–1095.** Blocking function called from `loop()` when `gameState == STARTING`. Counts down 3→2→1→GO:

- Each digit is displayed at text size 4 (large font) and accompanied by a 800 Hz beep
- After "GO!": 1200 Hz higher-pitch beep for 300ms
- Transitions `gameState = IN_GAME` and sets `displayDirty`

Being blocking here is acceptable — the countdown is expected to freeze all other processing for ~3 seconds, which is the intended user experience.

---

## 30. Lobby Broadcast

```cpp
void lobbyBroadcast()
```

**Lines 1100–1106.** Rate-limited to `LOBBY_BCAST_MS` (500ms). Broadcasts the public key and, if a team has been selected, the team selection. This runs every 500ms throughout the lobby phase so that any node that powers on late will receive the keys and team choices of nodes that came online earlier.

---

## 31. Periodic Sync

```cpp
void periodicSync()
```

**Lines 1111–1116.** Rate-limited to `SYNC_INTERVAL_MS` (30 seconds). Sends a `PKT_SYNC_REQUEST` broadcast during `IN_GAME`. Any peer that receives it will unicast back their full game table, which is then merged. This catches any drift that might occur if a packet was missed or if a node briefly lost contact.

---

## 32. IR Receive Check

```cpp
void checkIRReceive()
```

**Lines 1121–1138.** Called every loop iteration during `IN_GAME`. Checks the IRremoteESP8266 library's decode buffer. When a complete IR signal has been decoded:
- Checks that it is exactly `IR_PACKET_BITS` (32) bits long
- Calls `processIRHit` with the raw 32-bit value
- Calls `irRecv.resume()` to re-arm the receiver for the next packet

The secondary four receivers (`IR_BACK`, `IR_LEFT`, `IR_RIGHT`, `IR_GUN`) are monitored by the `hitDetected()` polling function but full packet decoding only happens on `PIN_IR_FRONT`. A complete implementation would run the software IR decoder on all five pins.

---

## 33. `setup()`

**Lines 1143–1207.** Runs once at power-on. Full initialisation sequence:

1. `Serial.begin(115200)` — for debug output
2. Configure all button pins as `INPUT_PULLUP` (active-low logic)
3. Configure motor pin as `OUTPUT`, pulled `LOW`
4. `irSend.begin()` and `irRecv.enableIRIn()` — start IR hardware
5. `Wire.begin(OLED_SDA, OLED_SCL)` and `oled.begin(...)` — start I2C and OLED; print "Booting..."
6. `FastLED.addLeds<WS2812B, PIN_WS2812B, GRB>(leds, NUM_LEDS)` — register LED strip with GRB colour order (most WS2812B LEDs use GRB, not RGB); set brightness to 100/255
7. `initEspNow()` — start radio
8. `WiFi.macAddress(myMAC)` — read and store own MAC; print to serial
9. `generateKeyPair()` — generate ECDH keypair for lobby
10. `memset` all state arrays to zero
11. `initTable()` — set all HP to 20
12. Set `myTeam = TEAM_NONE`, `gameState = LOBBY`, `displayDirty = true`
13. `sendSyncRequest()` — in case this node is joining a game already in progress; peers will respond with their current table
14. Display "Ready. Press TEAM to pick colour."

---

## 34. `loop()`

**Lines 1212–1254.** The main event loop. Runs repeatedly with a 10ms `delay` at the end.

Every iteration, regardless of game state:
```cpp
handleButtons();        // check all 4 buttons
updateWeaponMode();     // read potentiometer
checkSilentExpiry();    // auto-deactivate silent mode after 2 min
expirePending();        // discard unresolved hit entries after 2s
```

Then the state machine:

```
LOBBY     → lobbyBroadcast() + updateLEDs()
STARTING  → runStartingCountdown()     [blocking for ~3s]
IN_GAME   → checkIRReceive() + periodicSync() + updateLEDs()
ROUND_OVER→ updateLEDs()
RESETTING → doReset()
```

Finally, `displayUpdate()` redraws the OLED if `displayDirty` is set.

The 10ms loop delay keeps CPU usage reasonable and prevents the I2C bus and ESP-NOW stack from being starved. At 10ms per iteration, the effective input polling rate is 100 Hz — more than sufficient for button debounce and IR receive.

---

## Data Flow Summary

```
Player fires gun
    └─ fireGun()
         ├─ buildIRPacket() → irSend.sendNEC()   [IR, physical]
         └─ recordNonce()                         [local log]

Opponent vest receives IR
    └─ checkIRReceive() → processIRHit()
         ├─ vibrateHit() + ledHitFlash()          [immediate feedback]
         └─ sendHitClaim() × 3                    [ESP-NOW broadcast]

Shooter receives HIT_CLAIM
    └─ onDataRecv() → PKT_HIT_CLAIM handler
         └─ sendShotConfirm()                     [ESP-NOW broadcast]

All nodes receive both HIT_CLAIM + SHOT_CONFIRM
    └─ addHitClaim() / addShotConfirm()
         └─ tryCommitPending()
              ├─ validate (delta<0, version, arithmetic, nonce)
              ├─ update gameTable[victimID]
              ├─ trigger death/kill effects
              └─ checkWinCondition()
```

---

## Security Properties

| Threat | Mitigation in code |
|--------|--------------------|
| Fake HP increase | `mergeSlot`: `remote.value > local.value` → reject |
| Replay old valid packet | `nonceUsed()` check in `tryCommitPending` |
| Fake hit claim | Shooter must confirm with matching nonce; `PENDING_EXPIRE_MS` discards unmatched claims |
| Fake shot confirm | Victim must claim with matching nonce; unmatched confirms expire |
| Forged packet | `verifyHMAC()` with ECDH shared secret rejects it |
| Reboot to reset HP | Rebooted node starts at version 0; `mergeSlot` cannot override higher-version peers; ECDH key is gone so all packets rejected |
| Version skip attack | `version != slot.version + 1` → reject |

---

## Known Limitations & Extension Points

- **Trigger GPIO:** `fireGun()` is fully implemented but the trigger pin is not wired in this file. Connect your trigger switch to any free GPIO and call `fireGun()` from an interrupt or poll in the loop.
- **Secondary IR decoders:** Only `PIN_IR_FRONT` runs the full IR decode library. Full five-receiver decoding would require running the software decoder on each pin.
- **HMAC strength:** The current implementation uses a keyed CRC32. For stronger security, replace `computeHMAC` with SHA256-HMAC using the ESP32's hardware SHA peripheral — the function signature stays the same.
- **Player count:** `MAX_PLAYERS = 4` is defined at the top. Increasing it requires proportionally larger arrays (SRAM is the constraint on ESP32 — 520KB total).
- **Spectator node:** A fifth ESP32 can receive all ESP-NOW traffic and render a live scoreboard without any changes to this firmware.
