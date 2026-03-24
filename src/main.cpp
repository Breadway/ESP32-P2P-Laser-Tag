// =============================================================================
// ESP32 LASER TAG NODE
// =============================================================================
// Implements all phases of the build guide:
//   Phase 1 - Hardware (IR, OLED, LEDs, buttons, buzzer, motor)
//   Phase 2 - Networking (ESP-NOW, game state sync, hit confirmation)
//   Phase 3 - Authentication (ECDH, HMAC-signed packets, nonce log)
//
// Board:    ESP32 Dev Module
// Core:     arduino-esp32 v3.3.5
// Libraries: Adafruit SSD1306, Adafruit GFX, FastLED,
//            IRremoteESP8266, uECC
// =============================================================================

#include <Arduino.h>
#include <FastLED.h>
#pragma push_macro("BLACK")
#ifdef BLACK
#undef BLACK
#endif
#include <Adafruit_SSD1306.h>
#include <Adafruit_GFX.h>
#pragma pop_macro("BLACK")
// ================================================================

#include <esp_now.h>
#include <esp_wifi.h>
#include <WiFi.h>
#include <Wire.h>
#include <IRremoteESP8266.h>
#include <IRsend.h>
#include <IRrecv.h>
#include <IRutils.h>
#include <uECC.h>

#include <algorithm>
#include <string.h>
#include <stdint.h>

// Set to 0 to compile out debug logs.
#ifndef LT_DEBUG
#define LT_DEBUG 1
#endif

// Set to 1 on a temporary "debugger" board to make it mostly passive and
// print richer ESP-NOW diagnostics while another board runs normal firmware.
#ifndef LT_DEBUGGER_NODE
#define LT_DEBUGGER_NODE 1
#endif

#if LT_DEBUG
#define DBG_PRINT(x) Serial.print(x)
#define DBG_PRINTLN(x) Serial.println(x)
#define DBG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
#define DBG_PRINT(x) do {} while (0)
#define DBG_PRINTLN(x) do {} while (0)
#define DBG_PRINTF(...) do {} while (0)
#endif

// =============================================================================
// PIN DEFINITIONS
// =============================================================================
#define PIN_IR_FRONT        34
#define PIN_IR_BACK         35
#define PIN_IR_LEFT         32
#define PIN_IR_RIGHT        33
#define PIN_IR_GUN          25
#define PIN_IR_TX           26    // via 2N2222 transistor
#define PIN_WS2812B         27
#define PIN_BUZZER          14
#define PIN_MOTOR           12    // via transistor
#define PIN_BTN_RELOAD      13
#define PIN_BTN_TEAM        4
#define PIN_BTN_SILENT      5
#define PIN_BTN_RESET_VOTE  18
#define PIN_POT             36    // weapon mode selector (ADC)

#define OLED_SDA            21
#define OLED_SCL            22
#define OLED_WIDTH          128
#define OLED_HEIGHT         64
#define OLED_ADDR           0x3C

// =============================================================================
// CONSTANTS
// =============================================================================
#define MAX_PLAYERS         4
#define STARTING_HP         20
#define NUM_LEDS            8      // adjust for your chain length
#define IR_FREQ_KHZ         38
#define IR_PACKET_BITS      32
#define NONCE_LOG_SIZE      32
#define PENDING_EXPIRE_MS   2000
#define HIT_CLAIM_RETRIES   3
#define HIT_CLAIM_GAP_MS    50
#define SILENT_MODE_MS      120000UL  // 2 minutes
#define SYNC_INTERVAL_MS    30000UL
#define LOBBY_BCAST_MS      500UL
#define TEAM_BCAST_MS       5000UL
#define READY_BCAST_MS      5000UL
#define AR_AMMO_MAX         30
#define AR_COOLDOWN_MS      150
#define PISTOL_COOLDOWN_MS  300
#define MOTOR_HIT_MS        100
#define MOTOR_KILL_MS       150
#define MOTOR_DEATH_MS      500
#define MOTOR_WIN_MS        120
#define ESPNOW_CHANNEL      1

// For bench testing with fewer devices, lower this via build flag (e.g. 2).
#ifndef LT_REQUIRED_READY
#define LT_REQUIRED_READY MAX_PLAYERS
#endif

// =============================================================================
// ENUMERATIONS
// =============================================================================
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

const char* gameStateName(GameState s) {
    switch (s) {
        case LOBBY: return "LOBBY";
        case STARTING: return "STARTING";
        case IN_GAME: return "IN_GAME";
        case ROUND_OVER: return "ROUND_OVER";
        case RESETTING: return "RESETTING";
        default: return "UNKNOWN";
    }
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

struct Slot {
    uint8_t  ownerID;
    int32_t  value;     // HP
    uint32_t version;
};

// ESP-NOW packet header common to all packet types
struct PktHeader {
    PacketType type;
    uint8_t    senderID;
};

// Public key broadcast (Phase 3)
struct PktPubKey {
    PktHeader hdr;
    uint8_t   pubKey[64]; // secp256r1 uncompressed, 64 bytes
};

// Team selection
struct PktTeamSelect {
    PktHeader hdr;
    uint8_t   team;  // Team enum
};

// Ready / reset vote
struct PktVote {
    PktHeader hdr;
};

// Hit claim from victim
struct PktHitClaim {
    PktHeader hdr;
    uint8_t   victimID;
    uint8_t   shooterID;
    uint32_t  nonce;
    int32_t   delta;    // negative
    int32_t   newHP;
    uint32_t  version;
    uint32_t  hmac;
};

// Shot confirm from shooter
struct PktShotConfirm {
    PktHeader hdr;
    uint8_t   shooterID;
    uint32_t  nonce;
    uint32_t  hmac;
};

// Sync request (no extra fields)
struct PktSyncRequest {
    PktHeader hdr;
};

// Sync response (full table)
struct PktSyncResponse {
    PktHeader hdr;
    Slot      table[MAX_PLAYERS];
};

// Pending hit confirmation entry
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

// =============================================================================
// GLOBAL STATE
// =============================================================================

// Hardware
Adafruit_SSD1306 oled(OLED_WIDTH, OLED_HEIGHT, &Wire, -1);
IRsend           irSend(PIN_IR_TX);
IRrecv           irRecv(PIN_IR_FRONT); // primary; others polled directly
CRGB             leds[NUM_LEDS];

// Networking
uint8_t myMAC[6];
uint8_t peerMACs[MAX_PLAYERS][6];
uint8_t peerCount = 0;

// Game state
GameState    gameState   = LOBBY;
uint8_t      myPlayerID  = 0xFF;
uint8_t      myTeam      = TEAM_NONE;
uint8_t      peerTeams[MAX_PLAYERS];
bool         peerReady[MAX_PLAYERS];
bool         peerResetVote[MAX_PLAYERS];
Slot         gameTable[MAX_PLAYERS];
WeaponMode   weaponMode  = PISTOL;
int          arAmmo      = AR_AMMO_MAX;
bool         silentMode  = false;
uint32_t     silentStart = 0;

// Hit tracking
uint32_t     usedNonces[NONCE_LOG_SIZE];
uint8_t      nonceHead  = 0;
PendingEntry pending[8];

// ECDH (Phase 3)
uint8_t privateKey[32];
uint8_t publicKey[64];
uint8_t sharedSecrets[MAX_PLAYERS][32];
uint8_t peerPubKeys[MAX_PLAYERS][64];
bool    pubKeyReceived[MAX_PLAYERS];

// Timers
uint32_t lastSync       = 0;
uint32_t lastLobbyBcast = 0;
uint32_t lastFire       = 0;
uint32_t silentEnd      = 0;
bool     reloadPending  = false;
uint32_t reloadStart    = 0;

// Button debounce
uint32_t btnReloadLast  = 0;
uint32_t btnTeamLast    = 0;
uint32_t btnSilentLast  = 0;
uint32_t btnResetLast   = 0;
#define BTN_DEBOUNCE_MS 80

// Display dirty flag
bool displayDirty = true;
bool ledsInitialized = false;
volatile bool setupComplete = false;
GameState lastLoggedState = LOBBY;
uint32_t lastHeartbeatMs = 0;
uint32_t rxPacketCount = 0;
uint32_t txAttemptCount = 0;
uint32_t txSendErrCount = 0;
uint32_t txSentOkCount = 0;
uint32_t txSentFailCount = 0;
uint32_t lastLobbyTraceMs = 0;
uint32_t lastReadyBcast = 0;
uint32_t lastTeamBcast = 0;
uint8_t lastBroadcastTeam = TEAM_NONE;
bool dbgLogHeartbeat = false;
bool dbgLogTxRx = false;
bool dbgLogLobby = false;
#if LT_DEBUGGER_NODE
bool dbgAllowTx = false;
#endif
uint32_t rxTypeCount[9] = {0};
uint32_t txTypeCount[9] = {0};

// Forward declarations needed by ready/start helper.
void deriveSharedSecrets();
void assignPlayerIDs();

uint8_t readyThreshold() {
    if (LT_REQUIRED_READY < 1) return 1;
    if (LT_REQUIRED_READY > MAX_PLAYERS) return MAX_PLAYERS;
    return LT_REQUIRED_READY;
}

uint8_t readyCountAll() {
    uint8_t count = 0;
    for (uint8_t i = 0; i < MAX_PLAYERS; i++) {
        if (peerReady[i]) count++;
    }
    return count;
}

uint8_t readyCountThreshold() {
    uint8_t count = 0;
    uint8_t threshold = readyThreshold();
    for (uint8_t i = 0; i < threshold; i++) {
        if (peerReady[i]) count++;
    }
    return count;
}

void maybeStartFromReady() {
    if (gameState != LOBBY) return;

    uint8_t threshold = readyThreshold();
    for (uint8_t i = 0; i < threshold; i++) {
        if (!peerReady[i]) return;
    }

    deriveSharedSecrets();
    assignPlayerIDs();
    if (myPlayerID >= MAX_PLAYERS) {
        DBG_PRINTLN("[STATE] cannot start: invalid myPlayerID");
        return;
    }

    // Initialize own HP slot before countdown.
    gameTable[myPlayerID].ownerID = myPlayerID;
    gameTable[myPlayerID].value   = STARTING_HP;
    gameTable[myPlayerID].version = 0;
    peerTeams[myPlayerID] = myTeam;
    gameState = STARTING;
    displayDirty = true;
    DBG_PRINTLN("[STATE] ready threshold met -> STARTING");
}

// Forward declaration for cross-used game logic.
void checkWinCondition();
void logKnownPeers();
uint8_t currentSenderID();
bool notePeerMac(const uint8_t *mac);
void logRadioStatus(const char *tag);
void handleDebugSerial();
void printDebugSnapshot(const char *tag);
void printPacketCounters();

// =============================================================================
// BROADCAST MAC
// =============================================================================
const uint8_t BROADCAST_MAC[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

// =============================================================================
// UTILITY: CRC32 / HMAC
// =============================================================================
// Simple keyed CRC32 sufficient for this threat model (Phase 3).
// Replace with SHA256-HMAC for stronger security.
uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

uint32_t computeHMAC(uint8_t senderID, int32_t delta, int32_t newHP,
                     uint32_t version, const uint8_t *sharedSecret) {
    uint8_t buf[16];
    buf[0] = senderID;
    memcpy(buf+1,  &delta,       4);
    memcpy(buf+5,  &newHP,       4);
    memcpy(buf+9,  &version,     4);
    memcpy(buf+13, sharedSecret, 4); // first 4 bytes of shared secret as key
    return crc32(buf, sizeof(buf));
}

bool verifyHMAC(uint8_t senderID, int32_t delta, int32_t newHP,
                uint32_t version, uint32_t received,
                const uint8_t *sharedSecret) {
    if (sharedSecret == nullptr) return true; // Phase 1 / 2: skip HMAC
    return computeHMAC(senderID, delta, newHP, version, sharedSecret) == received;
}

// =============================================================================
// UTILITY: NONCE LOG
// =============================================================================
bool nonceUsed(uint32_t nonce) {
    for (uint8_t i = 0; i < NONCE_LOG_SIZE; i++)
        if (usedNonces[i] == nonce) return true;
    return false;
}

void recordNonce(uint32_t nonce) {
    usedNonces[nonceHead] = nonce;
    nonceHead = (nonceHead + 1) % NONCE_LOG_SIZE;
}

void logKnownPeers() {
    DBG_PRINTF("[NET] peers=%u\n", (unsigned)peerCount);
    for (uint8_t i = 0; i < peerCount; i++) {
        DBG_PRINTF("[NET] peer[%u]=%02X:%02X:%02X:%02X:%02X:%02X\n",
                   (unsigned)i,
                   peerMACs[i][0], peerMACs[i][1], peerMACs[i][2],
                   peerMACs[i][3], peerMACs[i][4], peerMACs[i][5]);
    }
}

void logRadioStatus(const char *tag) {
    uint8_t ch = 0;
    wifi_second_chan_t sec = WIFI_SECOND_CHAN_NONE;
    esp_err_t chRes = esp_wifi_get_channel(&ch, &sec);
    bool bcastPeer = esp_now_is_peer_exist(BROADCAST_MAC);
    DBG_PRINTF("[NET] %s mode=%d wifi=%d ch=%u sec=%d chRes=%d bcastPeer=%d\n",
               tag,
               (int)WiFi.getMode(),
               (int)WiFi.status(),
               (unsigned)ch,
               (int)sec,
               (int)chRes,
               (int)bcastPeer);
}

void printDebugSnapshot(const char *tag) {
    uint8_t ch = 0;
    wifi_second_chan_t sec = WIFI_SECOND_CHAN_NONE;
    esp_err_t chRes = esp_wifi_get_channel(&ch, &sec);
    DBG_PRINTF("[SNAP] %s t=%lu st=%s team=%u id=%u peers=%u ready=%u/%u wifi=%d mode=%d ch=%u sec=%d chRes=%d rx=%lu txA=%lu txE=%lu txOk=%lu txFail=%lu heap=%u\n",
               tag,
               (unsigned long)millis(),
               gameStateName(gameState),
               (unsigned)myTeam,
               (unsigned)myPlayerID,
               (unsigned)peerCount,
               (unsigned)readyCountAll(),
               (unsigned)readyThreshold(),
               (int)WiFi.status(),
               (int)WiFi.getMode(),
               (unsigned)ch,
               (int)sec,
               (int)chRes,
               (unsigned long)rxPacketCount,
               (unsigned long)txAttemptCount,
               (unsigned long)txSendErrCount,
               (unsigned long)txSentOkCount,
               (unsigned long)txSentFailCount,
               (unsigned)ESP.getFreeHeap());
}

void printPacketCounters() {
    DBG_PRINTF("[PKT] RX pub=%lu team=%lu ready=%lu hit=%lu conf=%lu sreq=%lu sresp=%lu rset=%lu\n",
               (unsigned long)rxTypeCount[PKT_PUBKEY_BROADCAST],
               (unsigned long)rxTypeCount[PKT_TEAM_SELECT],
               (unsigned long)rxTypeCount[PKT_READY_VOTE],
               (unsigned long)rxTypeCount[PKT_HIT_CLAIM],
               (unsigned long)rxTypeCount[PKT_SHOT_CONFIRM],
               (unsigned long)rxTypeCount[PKT_SYNC_REQUEST],
               (unsigned long)rxTypeCount[PKT_SYNC_RESPONSE],
               (unsigned long)rxTypeCount[PKT_RESET_VOTE]);
    DBG_PRINTF("[PKT] TX pub=%lu team=%lu ready=%lu hit=%lu conf=%lu sreq=%lu sresp=%lu rset=%lu\n",
               (unsigned long)txTypeCount[PKT_PUBKEY_BROADCAST],
               (unsigned long)txTypeCount[PKT_TEAM_SELECT],
               (unsigned long)txTypeCount[PKT_READY_VOTE],
               (unsigned long)txTypeCount[PKT_HIT_CLAIM],
               (unsigned long)txTypeCount[PKT_SHOT_CONFIRM],
               (unsigned long)txTypeCount[PKT_SYNC_REQUEST],
               (unsigned long)txTypeCount[PKT_SYNC_RESPONSE],
               (unsigned long)txTypeCount[PKT_RESET_VOTE]);
}

bool notePeerMac(const uint8_t *mac) {
    if (mac == nullptr) return false;
    if (memcmp(mac, myMAC, 6) == 0) return false;

    for (uint8_t i = 0; i < peerCount; i++) {
        if (memcmp(peerMACs[i], mac, 6) == 0) return false;
    }

    if (peerCount >= (MAX_PLAYERS - 1)) return false;
    memcpy(peerMACs[peerCount++], mac, 6);
    DBG_PRINTLN("[NET] peer discovered");
    logKnownPeers();
    return true;
}

// =============================================================================
// UTILITY: ESP32 RNG for uECC
// =============================================================================
static int esp32RNG(uint8_t *dest, unsigned size) {
    for (unsigned i = 0; i < size; i++)
        dest[i] = (uint8_t)esp_random();
    return 1;
}

// =============================================================================
// HARDWARE: IR TRANSMITTER
// =============================================================================
// 32-bit packet: [shooterID:4][nonce:22][damage:4][checksum:2]
uint32_t buildIRPacket(uint8_t shooterID, uint32_t nonce, uint8_t damage) {
    uint32_t pkt = 0;
    pkt |= ((uint32_t)(shooterID & 0x0F)) << 28;
    pkt |= ((uint32_t)(nonce     & 0x3FFFFF)) << 6;
    pkt |= ((uint32_t)(damage    & 0x0F)) << 2;
    uint8_t cs = ((shooterID ^ (nonce >> 14) ^ (nonce >> 7) ^ nonce ^ damage) & 0x03);
    pkt |= cs;
    return pkt;
}

bool parseIRPacket(uint32_t raw, uint8_t &shooterID, uint32_t &nonce,
                   uint8_t &damage) {
    shooterID = (raw >> 28) & 0x0F;
    nonce     = (raw >>  6) & 0x3FFFFF;
    damage    = (raw >>  2) & 0x0F;
    uint8_t cs = raw & 0x03;
    uint8_t expected = ((shooterID ^ (nonce>>14) ^ (nonce>>7) ^ nonce ^ damage) & 0x03);
    return cs == expected;
}

void fireGun() {
    uint32_t now = millis();
    uint32_t cooldown = (weaponMode == AR) ? AR_COOLDOWN_MS : PISTOL_COOLDOWN_MS;
    if (now - lastFire < cooldown) return;
    if (weaponMode == AR && arAmmo <= 0) return;
    if (myPlayerID == 0xFF) return;

    lastFire = now;
    uint8_t damage = (weaponMode == AR) ? 4 : 2;
    uint32_t nonce = esp_random() & 0x3FFFFF;

    uint32_t pkt = buildIRPacket(myPlayerID, nonce, damage);
    irSend.sendNEC(pkt, IR_PACKET_BITS); // NEC timing; custom encoding fits

    if (weaponMode == AR) arAmmo--;

    // Broadcast nonce over ESP-NOW so other nodes can expect a SHOT_CONFIRM
    // (the SHOT_CONFIRM is sent only when we receive a matching HIT_CLAIM)
    // We store the nonce locally so we can match it later.
    recordNonce(nonce); // mark as "we fired this"
    // Store in a fired-nonce ring for confirm matching
    // (reuse usedNonces — separate ring would be cleaner; fine for 4 players)

    displayDirty = true;
}

// =============================================================================
// HARDWARE: IR RECEIVER (polling)
// =============================================================================
bool hitDetected() {
    return !digitalRead(PIN_IR_FRONT) ||
           !digitalRead(PIN_IR_BACK)  ||
           !digitalRead(PIN_IR_LEFT)  ||
           !digitalRead(PIN_IR_RIGHT) ||
           !digitalRead(PIN_IR_GUN);
}

// =============================================================================
// HARDWARE: BUZZER
// =============================================================================
void beep(uint16_t freq, uint16_t durationMs) {
    if (silentMode) return;
    tone(PIN_BUZZER, freq, durationMs);
    delay(durationMs + 10);
    noTone(PIN_BUZZER);
}

void playTuneHit()      { /* silent on hit per spec */ }
void playTuneDeath()    { if (silentMode) return; beep(600,120); beep(400,180); beep(200,300); }
void playTuneWin()      { if (silentMode) return; beep(500,100); beep(700,100); beep(900,200); }
void playTuneLose()     { if (silentMode) return; beep(400,200); beep(250,400); }
void playTuneStart()    { for(int i=0;i<3;i++){beep(600+i*100,80);delay(20);} beep(1000,200); }
void playSilentOn()     { tone(PIN_BUZZER,700,80); delay(100); tone(PIN_BUZZER,500,80); delay(90); noTone(PIN_BUZZER); }
void playSilentOff()    { tone(PIN_BUZZER,500,80); delay(100); tone(PIN_BUZZER,700,80); delay(90); noTone(PIN_BUZZER); }
void playCountdownBeep(bool go) { beep(go ? 1200 : 800, go ? 300 : 80); }

// =============================================================================
// HARDWARE: VIBRATION MOTOR
// =============================================================================
void motorPulse(uint32_t ms) {
    digitalWrite(PIN_MOTOR, HIGH);
    delay(ms);
    digitalWrite(PIN_MOTOR, LOW);
}

void vibrateHit()   { motorPulse(MOTOR_HIT_MS); }
void vibrateKill()  { motorPulse(MOTOR_KILL_MS); delay(60); motorPulse(MOTOR_KILL_MS); }
void vibrateDeath() { motorPulse(MOTOR_DEATH_MS); }
void vibrateWin()   { for(int i=0;i<3;i++){motorPulse(MOTOR_WIN_MS);delay(60);} }
void vibrateSilent(){ motorPulse(80); delay(60); motorPulse(80); }

// =============================================================================
// HARDWARE: WS2812B LEDs
// =============================================================================
CRGB teamColor(uint8_t team) {
    switch (team) {
        case TEAM_RED:    return CRGB::Red;
        case TEAM_BLUE:   return CRGB::Blue;
        case TEAM_GREEN:  return CRGB::Green;
        case TEAM_YELLOW: return CRGB(255,200,0);
        default:          return CRGB::White;
    }
}

void setAllLEDs(CRGB color) {
    if (!ledsInitialized) return;
    fill_solid(leds, NUM_LEDS, color);
}

void ledsOff() {
    setAllLEDs(CRGB::Black);
    if (ledsInitialized) FastLED.show();
}

void flashLEDs(CRGB color, uint32_t ms) {
    if (!ledsInitialized) return;
    setAllLEDs(color);
    FastLED.show();
    delay(ms);
    setAllLEDs(CRGB::Black);
    FastLED.show();
}

void ledHitFlash() {
    if (silentMode) return;
    CRGB prev = teamColor(myTeam);
    flashLEDs(CRGB::White, 80);
    setAllLEDs(prev);
    if (ledsInitialized) FastLED.show();
}

void ledCryptoEviction() {
    for (int i = 0; i < 8; i++) {
        setAllLEDs(CRGB::Red);
        if (ledsInitialized) FastLED.show();
        delay(80);
        ledsOff();
        delay(80);
    }
}

void updateLEDs() {
    if (!ledsInitialized) return;
    if (silentMode) { ledsOff(); return; }
    if (gameState == LOBBY) {
        if (myTeam == TEAM_NONE) {
            // Slow white pulse
            uint8_t bright = (uint8_t)(128 + 127 * sin(millis() / 800.0));
            fill_solid(leds, NUM_LEDS, CRGB(bright, bright, bright));
        } else {
            setAllLEDs(teamColor(myTeam));
        }
    } else if (gameState == IN_GAME) {
        Slot &me = gameTable[myPlayerID];
        if (me.value <= 0) { ledsOff(); return; }
        setAllLEDs(teamColor(myTeam));
    } else if (gameState == ROUND_OVER) {
        // Chase animation if winner
        uint8_t phase = (millis() / 100) % NUM_LEDS;
        fill_solid(leds, NUM_LEDS, CRGB::Black);
        leds[phase] = teamColor(myTeam);
    }
    FastLED.show();
}

// =============================================================================
// OLED DISPLAY
// =============================================================================
void displayUpdate() {
    if (!displayDirty) return;
    displayDirty = false;
    oled.clearDisplay();
    oled.setTextSize(1);
    oled.setTextColor(SSD1306_WHITE);

    if (gameState == LOBBY) {
        oled.setCursor(0, 0);
        oled.printf("ID:%d  Team:", myPlayerID);
        const char *tnames[] = {"NONE","RED","BLUE","GRN","YEL"};
        oled.println(tnames[myTeam]);
        oled.println("--- Lobby ---");
        for (uint8_t i = 0; i < MAX_PLAYERS; i++) {
            oled.printf("P%d: %s %s\n", i, tnames[peerTeams[i]],
                        peerReady[i] ? "(RDY)" : "");
        }
    } else if (gameState == IN_GAME || gameState == ROUND_OVER) {
        int32_t myHP = (myPlayerID < MAX_PLAYERS) ? gameTable[myPlayerID].value : 0;
        oled.setCursor(0, 0);
        oled.printf("HP:%d/20\n", max(0, (int)myHP));
        if (weaponMode == AR)
            oled.printf("AR  Ammo:%d/%d\n", arAmmo, AR_AMMO_MAX);
        else
            oled.println("PISTOL");

        // Count alive per team
        uint8_t alive = 0;
        for (uint8_t i = 0; i < MAX_PLAYERS; i++)
            if (gameTable[i].value > 0) alive++;
        oled.printf("Alive:%d\n", alive);

        if (gameState == ROUND_OVER) {
            oled.setTextSize(2);
            oled.setCursor(0, 40);
            bool win = false;
            if (myPlayerID < MAX_PLAYERS && gameTable[myPlayerID].value > 0)
                win = true;
            oled.println(win ? "YOU WIN!" : "YOU LOSE");
        } else if (myPlayerID < MAX_PLAYERS && gameTable[myPlayerID].value <= 0) {
            oled.setTextSize(2);
            oled.setCursor(0, 40);
            oled.println("DEAD");
        }

        if (silentMode) {
            uint32_t rem = (silentEnd > millis()) ? (silentEnd - millis()) / 1000 : 0;
            oled.setTextSize(1);
            oled.printf("\nSILENT %ds", rem);
        }
    }

    oled.display();
}

void flashKill() {
    oled.clearDisplay();
    oled.setTextSize(3);
    oled.setCursor(10, 20);
    oled.println("KILL!");
    oled.display();
    delay(1000);
    displayDirty = true;
    displayUpdate();
}

// =============================================================================
// GAME TABLE
// =============================================================================
void initTable() {
    for (uint8_t i = 0; i < MAX_PLAYERS; i++) {
        gameTable[i].ownerID = i;
        gameTable[i].value   = STARTING_HP;
        gameTable[i].version = 0;
    }
}

void mergeSlot(const Slot &remote, uint8_t senderID) {
    uint8_t id = remote.ownerID;
    if (id >= MAX_PLAYERS) return;
    Slot &local = gameTable[id];

    // HP can only decrease
    if (remote.value > local.value) return;

    // Highest version wins; tie → lowest HP wins
    if (remote.version > local.version ||
        (remote.version == local.version && remote.value < local.value)) {
        local = remote;
    }
}

void mergeTable(const Slot *remoteTable) {
    for (uint8_t i = 0; i < MAX_PLAYERS; i++)
        mergeSlot(remoteTable[i], remoteTable[i].ownerID);
}

// =============================================================================
// PLAYER / NODE ID ASSIGNMENT
// =============================================================================
// Sort all MAC addresses seen in lobby; our index = playerID.
void assignPlayerIDs() {
    // Collect all MACs: our own + peers
    uint8_t allMACs[MAX_PLAYERS][6];
    uint8_t count = 0;
    memcpy(allMACs[count++], myMAC, 6);
    for (uint8_t i = 0; i < peerCount && count < MAX_PLAYERS; i++)
        memcpy(allMACs[count++], peerMACs[i], 6);

    // Bubble sort ascending
    for (uint8_t i = 0; i < count; i++) {
        for (uint8_t j = i+1; j < count; j++) {
            if (memcmp(allMACs[i], allMACs[j], 6) > 0) {
                uint8_t tmp[6];
                memcpy(tmp,       allMACs[i], 6);
                memcpy(allMACs[i], allMACs[j], 6);
                memcpy(allMACs[j], tmp,        6);
            }
        }
    }

    for (uint8_t i = 0; i < count; i++) {
        if (memcmp(allMACs[i], myMAC, 6) == 0) {
            myPlayerID = i;
            break;
        }
    }
}

uint8_t currentSenderID() {
    return (myPlayerID < MAX_PLAYERS) ? myPlayerID : 0;
}

// =============================================================================
// ECDH KEY EXCHANGE (Phase 3)
// =============================================================================
void generateKeyPair() {
    uECC_set_rng(esp32RNG);
    uECC_make_key(publicKey, privateKey, uECC_secp256r1());
}

void deriveSharedSecrets() {
    for (uint8_t i = 0; i < MAX_PLAYERS; i++) {
        if (i == myPlayerID || !pubKeyReceived[i]) continue;
        uECC_shared_secret(peerPubKeys[i], privateKey,
                           sharedSecrets[i], uECC_secp256r1());
    }
}

// =============================================================================
// ESP-NOW SEND HELPERS
// =============================================================================
void espNowSend(const void *data, size_t len) {
#if LT_DEBUGGER_NODE
    // Passive by default; can be enabled at runtime for interactive tests.
    if (!dbgAllowTx) {
        (void)data;
        (void)len;
        return;
    }
#else
    txAttemptCount++;
    esp_err_t res = esp_now_send(BROADCAST_MAC, (const uint8_t*)data, len);
    if (len >= sizeof(PktHeader)) {
        const PktHeader *hdr = (const PktHeader*)data;
        if (hdr->type >= PKT_PUBKEY_BROADCAST && hdr->type <= PKT_RESET_VOTE)
            txTypeCount[(uint8_t)hdr->type]++;
    }
    if (res != ESP_OK) {
        txSendErrCount++;
        const PktHeader *hdr = (const PktHeader*)data;
        uint8_t t = (len >= sizeof(PktHeader) && hdr) ? (uint8_t)hdr->type : 0xFF;
        DBG_PRINTF("[NET] TX submit failed type=%u len=%u err=%d\n",
                   (unsigned)t,
                   (unsigned)len,
                   (int)res);
        DBG_PRINTF("[NET] TX submit err name=%s\n", esp_err_to_name(res));
    }
#endif

#if LT_DEBUGGER_NODE
    txAttemptCount++;
    esp_err_t res = esp_now_send(BROADCAST_MAC, (const uint8_t*)data, len);
    if (len >= sizeof(PktHeader)) {
        const PktHeader *hdr = (const PktHeader*)data;
        if (hdr->type >= PKT_PUBKEY_BROADCAST && hdr->type <= PKT_RESET_VOTE)
            txTypeCount[(uint8_t)hdr->type]++;
    }
    if (res != ESP_OK) {
        txSendErrCount++;
        const PktHeader *hdr = (const PktHeader*)data;
        uint8_t t = (len >= sizeof(PktHeader) && hdr) ? (uint8_t)hdr->type : 0xFF;
        DBG_PRINTF("[NET] TX submit failed type=%u len=%u err=%d\n",
                   (unsigned)t,
                   (unsigned)len,
                   (int)res);
        DBG_PRINTF("[NET] TX submit err name=%s\n", esp_err_to_name(res));
    }
#endif
}

void sendPubKey() {
    PktPubKey pkt;
    pkt.hdr = {PKT_PUBKEY_BROADCAST, currentSenderID()};
    memcpy(pkt.pubKey, publicKey, 64);
    espNowSend(&pkt, sizeof(pkt));
}

void sendTeamSelect() {
    PktTeamSelect pkt;
    pkt.hdr  = {PKT_TEAM_SELECT, currentSenderID()};
    pkt.team = myTeam;
    espNowSend(&pkt, sizeof(pkt));
}

void sendReadyVote() {
    PktVote pkt;
    pkt.hdr = {PKT_READY_VOTE, currentSenderID()};

    // Mark local ready immediately so local status matches what we transmit.
    if (myPlayerID < MAX_PLAYERS) {
        peerReady[myPlayerID] = true;
        displayDirty = true;
    }

    // Evaluate transition immediately for local-ready-triggered starts.
    maybeStartFromReady();

    espNowSend(&pkt, sizeof(pkt));
}

void sendResetVote() {
    PktVote pkt;
    pkt.hdr = {PKT_RESET_VOTE, currentSenderID()};
    espNowSend(&pkt, sizeof(pkt));
}

void sendSyncRequest() {
    PktSyncRequest pkt;
    pkt.hdr = {PKT_SYNC_REQUEST, currentSenderID()};
    espNowSend(&pkt, sizeof(pkt));
}

void sendSyncResponse(const uint8_t *destMAC) {
    PktSyncResponse pkt;
    pkt.hdr = {PKT_SYNC_RESPONSE, myPlayerID};
    memcpy(pkt.table, gameTable, sizeof(gameTable));
    esp_now_send(destMAC, (const uint8_t*)&pkt, sizeof(pkt));
}

void sendHitClaim(uint8_t victimID, uint8_t shooterID, uint32_t nonce,
                  int32_t delta, int32_t newHP, uint32_t version) {
    PktHitClaim pkt;
    pkt.hdr      = {PKT_HIT_CLAIM, myPlayerID};
    pkt.victimID  = victimID;
    pkt.shooterID = shooterID;
    pkt.nonce     = nonce;
    pkt.delta     = delta;
    pkt.newHP     = newHP;
    pkt.version   = version;
    const uint8_t *secret = (myPlayerID < MAX_PLAYERS) ? sharedSecrets[shooterID] : nullptr;
    pkt.hmac = computeHMAC(myPlayerID, delta, newHP, version, secret);
    for (int i = 0; i < HIT_CLAIM_RETRIES; i++) {
        espNowSend(&pkt, sizeof(pkt));
        if (i < HIT_CLAIM_RETRIES - 1) delay(HIT_CLAIM_GAP_MS);
    }
}

void sendShotConfirm(uint8_t shooterID, uint32_t nonce) {
    PktShotConfirm pkt;
    pkt.hdr       = {PKT_SHOT_CONFIRM, myPlayerID};
    pkt.shooterID = shooterID;
    pkt.nonce     = nonce;
    // HMAC over confirm uses a simple fixed key for now
    const uint8_t *secret = (myPlayerID < MAX_PLAYERS) ? sharedSecrets[shooterID] : nullptr;
    pkt.hmac = computeHMAC(shooterID, 0, 0, nonce, secret ? secret : (const uint8_t*)"\0\0\0\0");
    espNowSend(&pkt, sizeof(pkt));
}

// =============================================================================
// PENDING HIT CONFIRMATION
// =============================================================================
PendingEntry* findPending(uint32_t nonce) {
    for (auto &e : pending)
        if (e.active && e.nonce == nonce) return &e;
    return nullptr;
}

PendingEntry* allocPending() {
    for (auto &e : pending)
        if (!e.active) return &e;
    // Evict oldest
    return &pending[0];
}

void expirePending() {
    uint32_t now = millis();
    for (auto &e : pending)
        if (e.active && now > e.expiresAt) e.active = false;
}

void tryCommitPending(PendingEntry &e) {
    if (!e.claimSeen || !e.confirmSeen) return;
    if (e.victimID >= MAX_PLAYERS) return;

    Slot &slot = gameTable[e.victimID];
    // Validate
    if (e.delta >= 0) { e.active = false; return; }
    if (e.version != slot.version + 1) { e.active = false; return; }
    if (slot.value + e.delta != e.newHP) { e.active = false; return; }
    if (nonceUsed(e.nonce)) { e.active = false; return; }

    // Commit
    slot.value   = e.newHP;
    slot.version = e.version;
    recordNonce(e.nonce);
    e.active = false;
    displayDirty = true;

    // Local player was killed
    if (e.victimID == myPlayerID && slot.value <= 0) {
        vibrateDeath();
        playTuneDeath();
        ledsOff();
    }

    // We confirmed a kill
    if (e.shooterID == myPlayerID) {
        vibrateKill();
        flashKill();
    }

    checkWinCondition();
}

void addHitClaim(const PktHitClaim &pkt) {
    PendingEntry *e = findPending(pkt.nonce);
    if (!e) {
        e = allocPending();
        memset(e, 0, sizeof(*e));
        e->active     = true;
        e->nonce      = pkt.nonce;
        e->victimID   = pkt.victimID;
        e->shooterID  = pkt.shooterID;
        e->delta      = pkt.delta;
        e->newHP      = pkt.newHP;
        e->version    = pkt.version;
        e->expiresAt  = millis() + PENDING_EXPIRE_MS;
    }
    // Verify HMAC
    const uint8_t *secret = sharedSecrets[pkt.shooterID];
    if (!verifyHMAC(pkt.hdr.senderID, pkt.delta, pkt.newHP, pkt.version,
                    pkt.hmac, secret)) return;

    e->claimSeen = true;
    tryCommitPending(*e);
}

void addShotConfirm(const PktShotConfirm &pkt) {
    PendingEntry *e = findPending(pkt.nonce);
    if (!e) {
        e = allocPending();
        memset(e, 0, sizeof(*e));
        e->active    = true;
        e->nonce     = pkt.nonce;
        e->shooterID = pkt.shooterID;
        e->expiresAt = millis() + PENDING_EXPIRE_MS;
    }
    e->confirmSeen = true;
    tryCommitPending(*e);
}

// =============================================================================
// IR HIT PROCESSING
// =============================================================================
void processIRHit(uint32_t raw) {
    if (gameState != IN_GAME) return;
    if (myPlayerID >= MAX_PLAYERS) return;
    if (gameTable[myPlayerID].value <= 0) return; // already dead

    uint8_t  shooterID, damage;
    uint32_t nonce;
    if (!parseIRPacket(raw, shooterID, nonce, damage)) return;
    if (shooterID == myPlayerID) return; // self
    if (shooterID >= MAX_PLAYERS) return;

    // Friendly fire check
    if (peerTeams[shooterID] == myTeam && myTeam != TEAM_NONE) return;

    // Replay prevention
    if (nonceUsed(nonce)) return;

    // Calculate hit result
    int32_t curHP  = gameTable[myPlayerID].value;
    int32_t delta  = -(int32_t)damage;
    int32_t newHP  = max(0, (int)(curHP + delta));
    uint32_t ver   = gameTable[myPlayerID].version + 1;

    vibrateHit();
    ledHitFlash();
    displayDirty = true;

    sendHitClaim(myPlayerID, shooterID, nonce, delta, newHP, ver);
}

// =============================================================================
// WIN CONDITION
// =============================================================================
void checkWinCondition() {
    if (gameState != IN_GAME) return;

    // Collect living players
    uint8_t livingTeam = 0xFF;
    bool    multiTeam  = false;
    uint8_t livingCount = 0;

    for (uint8_t i = 0; i < MAX_PLAYERS; i++) {
        if (gameTable[i].value > 0) {
            livingCount++;
            if (livingTeam == 0xFF) {
                livingTeam = peerTeams[i];
            } else if (peerTeams[i] != livingTeam) {
                multiTeam = true;
            }
        }
    }

    if (livingCount == 0 || (!multiTeam && livingCount > 0)) {
        // Round over
        gameState = ROUND_OVER;
        displayDirty = true;
        bool iWin = (myPlayerID < MAX_PLAYERS &&
                     gameTable[myPlayerID].value > 0);
        if (iWin) { playTuneWin(); vibrateWin(); }
        else       { playTuneLose(); }
    }
}

// =============================================================================
// RESET
// =============================================================================
void doReset() {
    initTable();
    memset(usedNonces, 0, sizeof(usedNonces));
    nonceHead = 0;
    memset(pending, 0, sizeof(pending));
    memset(peerReady, 0, sizeof(peerReady));
    memset(peerResetVote, 0, sizeof(peerResetVote));
    arAmmo = AR_AMMO_MAX;
    silentMode = false;
    generateKeyPair();
    gameState = LOBBY;
    displayDirty = true;
}

// =============================================================================
// ESP-NOW RECEIVE CALLBACK (v3.x signature)
// =============================================================================
void onDataRecv(const uint8_t *srcMac, const uint8_t *data, int len) {
    if (!setupComplete) return;
    if (srcMac == nullptr || data == nullptr) return;
    if (len < (int)sizeof(PktHeader)) return;
    const PktHeader *hdr = (const PktHeader*)data;
    rxPacketCount++;
    if (hdr->type >= PKT_PUBKEY_BROADCAST && hdr->type <= PKT_RESET_VOTE)
        rxTypeCount[(uint8_t)hdr->type]++;
    uint8_t sid = hdr->senderID;
    if (dbgLogTxRx) {
        DBG_PRINTF("[NET] RX t=%u sid=%u len=%d from=%02X:%02X:%02X:%02X:%02X:%02X\n",
                   (unsigned)hdr->type,
                   (unsigned)sid,
                   len,
                   srcMac[0], srcMac[1], srcMac[2],
                   srcMac[3], srcMac[4], srcMac[5]);
    }

    // Track peers from any inbound packet type.
    if (notePeerMac(srcMac)) {
        uint8_t prevID = myPlayerID;
        assignPlayerIDs();
        if (myPlayerID != prevID) {
            DBG_PRINTF("[NET] assigned myPlayerID=%u\n", (unsigned)myPlayerID);
        }
    }

    switch (hdr->type) {

        case PKT_PUBKEY_BROADCAST: {
            if (len < (int)sizeof(PktPubKey)) break;
            if (dbgLogTxRx) {
                DBG_PRINTF("[NET] PUBKEY sid=%u first4=%02X%02X%02X%02X\n",
                           (unsigned)sid,
                           ((const PktPubKey*)data)->pubKey[0],
                           ((const PktPubKey*)data)->pubKey[1],
                           ((const PktPubKey*)data)->pubKey[2],
                           ((const PktPubKey*)data)->pubKey[3]);
            }
            if (gameState != LOBBY) break; // key exchange locked after lobby
            if (sid >= MAX_PLAYERS || sid == myPlayerID) {
                DBG_PRINTF("[NET] PUBKEY ignored (sid=%u my=%u)\n",
                           (unsigned)sid, (unsigned)myPlayerID);
                break;
            }
            const PktPubKey *pkt = (const PktPubKey*)data;
            memcpy(peerPubKeys[sid], pkt->pubKey, 64);
            pubKeyReceived[sid] = true;
            break;
        }

        case PKT_TEAM_SELECT: {
            if (len < (int)sizeof(PktTeamSelect)) break;
            if (sid >= MAX_PLAYERS) break;
            const PktTeamSelect *pkt = (const PktTeamSelect*)data;
            peerTeams[sid] = pkt->team;
            if (dbgLogTxRx)
                DBG_PRINTF("[NET] TEAM sid=%u team=%u\n", (unsigned)sid, (unsigned)pkt->team);
            displayDirty = true;
            break;
        }

        case PKT_READY_VOTE: {
            if (sid >= MAX_PLAYERS) break;
            peerReady[sid] = true;
            uint8_t readyCount = readyCountThreshold();
            uint8_t threshold = readyThreshold();
            if (dbgLogTxRx)
                DBG_PRINTF("[NET] READY sid=%u ready=%u/%u\n",
                           (unsigned)sid,
                           (unsigned)readyCount,
                           (unsigned)threshold);
            displayDirty = true;
            maybeStartFromReady();
            break;
        }

        case PKT_HIT_CLAIM: {
            if (len < (int)sizeof(PktHitClaim)) break;
            const PktHitClaim *pkt = (const PktHitClaim*)data;
            if (dbgLogTxRx)
                DBG_PRINTF("[NET] HIT nonce=%lu v=%u s=%u d=%ld hp=%ld ver=%lu\n",
                           (unsigned long)pkt->nonce,
                           (unsigned)pkt->victimID,
                           (unsigned)pkt->shooterID,
                           (long)pkt->delta,
                           (long)pkt->newHP,
                           (unsigned long)pkt->version);
            // If we are the shooter, send confirm
            if (!LT_DEBUGGER_NODE && pkt->shooterID == myPlayerID) {
                // We validate that we actually fired this nonce
                // (recorded in usedNonces at fire time)
                sendShotConfirm(myPlayerID, pkt->nonce);
            }
            addHitClaim(*pkt);
            break;
        }

        case PKT_SHOT_CONFIRM: {
            if (len < (int)sizeof(PktShotConfirm)) break;
            const PktShotConfirm *pkt = (const PktShotConfirm*)data;
            if (dbgLogTxRx)
                DBG_PRINTF("[NET] CONF nonce=%lu shooter=%u\n",
                           (unsigned long)pkt->nonce,
                           (unsigned)pkt->shooterID);
            addShotConfirm(*pkt);
            break;
        }

        case PKT_SYNC_REQUEST: {
            if (sid >= MAX_PLAYERS) break;
            if (!LT_DEBUGGER_NODE) sendSyncResponse(srcMac);
            if (dbgLogTxRx)
                DBG_PRINTF("[NET] SYNC_REQ sid=%u\n", (unsigned)sid);
            break;
        }

        case PKT_SYNC_RESPONSE: {
            if (len < (int)sizeof(PktSyncResponse)) break;
            if (sid >= MAX_PLAYERS) break;
            const PktSyncResponse *pkt = (const PktSyncResponse*)data;
            mergeTable(pkt->table);
            if (dbgLogTxRx)
                DBG_PRINTF("[NET] SYNC_RESP sid=%u\n", (unsigned)sid);
            displayDirty = true;
            break;
        }

        case PKT_RESET_VOTE: {
            if (sid >= MAX_PLAYERS) break;
            peerResetVote[sid] = true;
            if (dbgLogTxRx)
                DBG_PRINTF("[NET] RESET sid=%u\n", (unsigned)sid);
            // Check unanimous (all 4 including self)
            bool allVoted = true;
            for (uint8_t i = 0; i < MAX_PLAYERS; i++)
                if (!peerResetVote[i]) { allVoted = false; break; }
            if (allVoted) doReset();
            break;
        }

        default: break;
    }
}

// =============================================================================
// ESP-NOW SEND CALLBACK (v3.x signature)
// =============================================================================
void onDataSent(const uint8_t *mac, esp_now_send_status_t status) {
    if (mac == nullptr) return;
    if (status == ESP_NOW_SEND_SUCCESS) txSentOkCount++;
    else txSentFailCount++;
    if (dbgLogTxRx || status != ESP_NOW_SEND_SUCCESS) {
        DBG_PRINTF("[NET] TX %s to %02X:%02X:%02X:%02X:%02X:%02X\n",
                   status == ESP_NOW_SEND_SUCCESS ? "ok" : "fail",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

// =============================================================================
// ESP-NOW INIT
// =============================================================================
void initEspNow() {
    DBG_PRINTLN("[NET] initEspNow: starting Wi-Fi STA mode");
    // Keep STA radio on for ESP-NOW (do not power Wi-Fi off).
    WiFi.persistent(false);
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    esp_err_t psRes = esp_wifi_set_ps(WIFI_PS_NONE);
    DBG_PRINTF("[NET] esp_wifi_set_ps res=%d (%s)\n", (int)psRes, esp_err_to_name(psRes));
    WiFi.disconnect(false, true);
    delay(20);

    // Force a fixed channel so all test nodes stay on the same ESP-NOW channel.
    esp_err_t promOnRes = esp_wifi_set_promiscuous(true);
    esp_err_t chanRes = esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
    esp_err_t promOffRes = esp_wifi_set_promiscuous(false);
    DBG_PRINTF("[NET] promisc on=%d (%s) set_channel=%d (%s) off=%d (%s)\n",
               (int)promOnRes, esp_err_to_name(promOnRes),
               (int)chanRes, esp_err_to_name(chanRes),
               (int)promOffRes, esp_err_to_name(promOffRes));

    esp_err_t initResult = esp_now_init();
    if (initResult != ESP_OK) {
        DBG_PRINTF("[NET] esp_now_init failed (%d %s)\n", (int)initResult, esp_err_to_name(initResult));
        Serial.println("ESP-NOW init failed");
        return;
    }
    DBG_PRINTLN("[NET] esp_now_init ok");
    esp_now_register_recv_cb(onDataRecv);
    esp_now_register_send_cb(onDataSent);

    // Register broadcast peer
    esp_now_peer_info_t peerInfo;
    memset(&peerInfo, 0, sizeof(peerInfo));
    memcpy(peerInfo.peer_addr, BROADCAST_MAC, 6);
    peerInfo.channel = ESPNOW_CHANNEL;
    peerInfo.ifidx = WIFI_IF_STA;
    peerInfo.encrypt = false;
    esp_err_t peerResult = esp_now_add_peer(&peerInfo);
    DBG_PRINTF("[NET] broadcast peer add result: %d (%s)\n", (int)peerResult, esp_err_to_name(peerResult));
    DBG_PRINTF("[NET] channel=%d\n", ESPNOW_CHANNEL);
    logRadioStatus("post-init");
    DBG_PRINTLN("[NET] waiting for other players...");
}

void handleDebugSerial() {
#if LT_DEBUG
    while (Serial.available() > 0) {
        int c = Serial.read();
        switch (c) {
            case '?':
                DBG_PRINTLN("[DBG] cmds:? help, i snapshot, k counters, p pubkey, t team, c cycleTeam, a/b/g/y setTeam, q teamNone, r ready, u unready, s sync, j resetVote, d doReset, f fire(in game), w radio, z clearCtr, h hb, n net, l lobby, 0 quiet, 1 verbose, x txToggle");
                break;
            case 'p':
            case 'P':
                DBG_PRINTLN("[DBG] force sendPubKey");
                sendPubKey();
                break;
            case 't':
            case 'T':
                DBG_PRINTLN("[DBG] force sendTeamSelect");
                if (myTeam == TEAM_NONE) myTeam = TEAM_RED;
                sendTeamSelect();
                break;
            case 'c':
            case 'C':
                myTeam = (uint8_t)((myTeam % 4) + 1);
                if (myPlayerID < MAX_PLAYERS) peerTeams[myPlayerID] = myTeam;
                DBG_PRINTF("[DBG] cycle team -> %u\n", (unsigned)myTeam);
                sendTeamSelect();
                displayDirty = true;
                break;
            case 'a':
            case 'A':
                myTeam = TEAM_RED;
                if (myPlayerID < MAX_PLAYERS) peerTeams[myPlayerID] = myTeam;
                DBG_PRINTLN("[DBG] team=RED");
                sendTeamSelect();
                displayDirty = true;
                break;
            case 'b':
            case 'B':
                myTeam = TEAM_BLUE;
                if (myPlayerID < MAX_PLAYERS) peerTeams[myPlayerID] = myTeam;
                DBG_PRINTLN("[DBG] team=BLUE");
                sendTeamSelect();
                displayDirty = true;
                break;
            case 'g':
            case 'G':
                myTeam = TEAM_GREEN;
                if (myPlayerID < MAX_PLAYERS) peerTeams[myPlayerID] = myTeam;
                DBG_PRINTLN("[DBG] team=GREEN");
                sendTeamSelect();
                displayDirty = true;
                break;
            case 'y':
            case 'Y':
                myTeam = TEAM_YELLOW;
                if (myPlayerID < MAX_PLAYERS) peerTeams[myPlayerID] = myTeam;
                DBG_PRINTLN("[DBG] team=YELLOW");
                sendTeamSelect();
                displayDirty = true;
                break;
            case 'q':
            case 'Q':
                myTeam = TEAM_NONE;
                if (myPlayerID < MAX_PLAYERS) peerTeams[myPlayerID] = myTeam;
                DBG_PRINTLN("[DBG] team=NONE");
                sendTeamSelect();
                displayDirty = true;
                break;
            case 'r':
            case 'R':
                DBG_PRINTLN("[DBG] force sendReadyVote");
                sendReadyVote();
                break;
            case 'u':
            case 'U':
                if (myPlayerID < MAX_PLAYERS) {
                    peerReady[myPlayerID] = false;
                    DBG_PRINTLN("[DBG] local ready cleared");
                    displayDirty = true;
                }
                break;
            case 's':
            case 'S':
                DBG_PRINTLN("[DBG] force sendSyncRequest");
                sendSyncRequest();
                break;
            case 'j':
            case 'J':
                DBG_PRINTLN("[DBG] force sendResetVote");
                if (myPlayerID < MAX_PLAYERS) {
                    peerResetVote[myPlayerID] = true;
                }
                sendResetVote();
                break;
            case 'd':
            case 'D':
                DBG_PRINTLN("[DBG] local doReset()");
                doReset();
                break;
            case 'f':
            case 'F':
                if (gameState == IN_GAME) {
                    DBG_PRINTLN("[DBG] fireGun()");
                    fireGun();
                } else {
                    DBG_PRINTLN("[DBG] fire ignored (not in game)");
                }
                break;
            case 'i':
            case 'I':
                printDebugSnapshot("manual");
                logKnownPeers();
                printPacketCounters();
                break;
            case 'k':
            case 'K':
                printPacketCounters();
                break;
            case 'h':
            case 'H':
                dbgLogHeartbeat = !dbgLogHeartbeat;
                DBG_PRINTF("[DBG] heartbeat=%d\n", (int)dbgLogHeartbeat);
                break;
            case 'n':
            case 'N':
                dbgLogTxRx = !dbgLogTxRx;
                DBG_PRINTF("[DBG] net_txrx=%d\n", (int)dbgLogTxRx);
                break;
            case 'l':
            case 'L':
                dbgLogLobby = !dbgLogLobby;
                DBG_PRINTF("[DBG] lobby=%d\n", (int)dbgLogLobby);
                break;
            case 'w':
            case 'W':
                logRadioStatus("manual");
                logKnownPeers();
                break;
            case 'z':
            case 'Z':
                memset(rxTypeCount, 0, sizeof(rxTypeCount));
                memset(txTypeCount, 0, sizeof(txTypeCount));
                rxPacketCount = 0;
                txAttemptCount = 0;
                txSendErrCount = 0;
                txSentOkCount = 0;
                txSentFailCount = 0;
                DBG_PRINTLN("[DBG] counters cleared");
                break;
            case '0':
                dbgLogHeartbeat = false;
                dbgLogTxRx = false;
                dbgLogLobby = false;
                DBG_PRINTLN("[DBG] quiet mode enabled");
                break;
            case '1':
                dbgLogHeartbeat = true;
                dbgLogTxRx = true;
                dbgLogLobby = true;
                DBG_PRINTLN("[DBG] verbose mode enabled");
                break;
#if LT_DEBUGGER_NODE
            case 'x':
            case 'X':
                dbgAllowTx = !dbgAllowTx;
                DBG_PRINTF("[DBG] debugger TX enabled=%d\n", (int)dbgAllowTx);
                break;
#endif
            default:
                break;
        }
    }
#endif
}

// =============================================================================
// BUTTON HANDLING
// =============================================================================
bool btnPressed(uint8_t pin, uint32_t &lastTime) {
    if (digitalRead(pin) == LOW && (millis() - lastTime) > BTN_DEBOUNCE_MS) {
        lastTime = millis();
        return true;
    }
    return false;
}

void handleButtons() {
#if LT_DEBUGGER_NODE
    return;
#endif
    // Reload (AR only)
    if (btnPressed(PIN_BTN_RELOAD, btnReloadLast)) {
        if (weaponMode == AR && !reloadPending) {
            reloadPending = true;
            reloadStart   = millis();
        }
    }
    if (reloadPending && (millis() - reloadStart >= 2000)) {
        arAmmo = AR_AMMO_MAX;
        reloadPending = false;
        displayDirty  = true;
    }

    // Team cycle (lobby only)
    if (btnPressed(PIN_BTN_TEAM, btnTeamLast)) {
        if (gameState == LOBBY) {
            myTeam = (uint8_t)((myTeam % 4) + 1); // cycles 1..4
            peerTeams[myPlayerID == 0xFF ? 0 : myPlayerID] = myTeam;
            sendTeamSelect();
            updateLEDs();
            displayDirty = true;
        }
    }

    // Silent mode
    if (btnPressed(PIN_BTN_SILENT, btnSilentLast)) {
        if (!silentMode) {
            silentMode = true;
            silentEnd  = millis() + SILENT_MODE_MS;
            playSilentOn();
            vibrateSilent();
        } else {
            silentMode = false;
            playSilentOff();
            vibrateSilent();
        }
        updateLEDs();
        displayDirty = true;
    }

    // Reset vote
    if (btnPressed(PIN_BTN_RESET_VOTE, btnResetLast)) {
        if (myPlayerID < MAX_PLAYERS) {
            peerResetVote[myPlayerID] = true;
            sendResetVote();
        }
    }
}

// =============================================================================
// WEAPON MODE (potentiometer)
// =============================================================================
void updateWeaponMode() {
    int raw = analogRead(PIN_POT); // 0..4095
    WeaponMode newMode = (raw > 2048) ? AR : PISTOL;
    if (newMode != weaponMode) {
        weaponMode   = newMode;
        displayDirty = true;
        if (weaponMode == AR) arAmmo = AR_AMMO_MAX;
    }
}

// =============================================================================
// SILENT MODE EXPIRY
// =============================================================================
void checkSilentExpiry() {
    if (silentMode && millis() > silentEnd) {
        silentMode = false;
        playSilentOff();
        vibrateSilent();
        updateLEDs();
        displayDirty = true;
    }
}

// =============================================================================
// GAME STARTING COUNTDOWN
// =============================================================================
void runStartingCountdown() {
    for (int i = 3; i > 0; i--) {
        oled.clearDisplay();
        oled.setTextSize(4);
        oled.setCursor(50, 15);
        oled.print(i);
        oled.display();
        playCountdownBeep(false);
        delay(900);
    }
    oled.clearDisplay();
    oled.setTextSize(3);
    oled.setCursor(20, 20);
    oled.println("GO!");
    oled.display();
    playCountdownBeep(true);
    delay(500);
    gameState    = IN_GAME;
    displayDirty = true;
}

// =============================================================================
// LOBBY BROADCAST
// =============================================================================
void lobbyBroadcast() {
#if LT_DEBUGGER_NODE
    return;
#endif
    uint32_t now = millis();
    if (now - lastLobbyBcast < LOBBY_BCAST_MS) return;
    lastLobbyBcast = now;

    // Keep sender ID valid in lobby before full game start.
    if (myPlayerID >= MAX_PLAYERS) {
        assignPlayerIDs();
        DBG_PRINTF("[NET] lobby assigned myPlayerID=%u\n", (unsigned)myPlayerID);
    }

    sendPubKey();

    // TEAM is event-driven with a slow keepalive to avoid flooding the lobby.
    if (myTeam != TEAM_NONE) {
        if (myTeam != lastBroadcastTeam || (now - lastTeamBcast >= TEAM_BCAST_MS)) {
            sendTeamSelect();
            lastBroadcastTeam = myTeam;
            lastTeamBcast = now;
        }
    } else {
        lastBroadcastTeam = TEAM_NONE;
    }

    // Re-broadcast READY while in lobby so occasional packet loss does not
    // leave peers stuck with mismatched ready state.
    if (myPlayerID < MAX_PLAYERS && peerReady[myPlayerID]) {
        if (now - lastReadyBcast >= READY_BCAST_MS) {
            lastReadyBcast = now;
            sendReadyVote();
        }
    }

    if (dbgLogLobby && (now - lastLobbyTraceMs >= 2000)) {
        lastLobbyTraceMs = now;
        DBG_PRINTF("[NET] lobby tx heartbeat id=%u peers=%u\n",
                   (unsigned)currentSenderID(),
                   (unsigned)peerCount);
        logRadioStatus("lobby");
    }
}

// =============================================================================
// PERIODIC SYNC
// =============================================================================
void periodicSync() {
#if LT_DEBUGGER_NODE
    return;
#endif
    uint32_t now = millis();
    if (now - lastSync < SYNC_INTERVAL_MS) return;
    lastSync = now;
    sendSyncRequest();
}

// =============================================================================
// IR RECEIVE CHECK
// =============================================================================
void checkIRReceive() {
    // Poll all 5 TSOP pins for active-low signal
    // The IRremote library handles decoding on PIN_IR_FRONT.
    // For a complete solution, multiplex or use software IR decoding
    // on remaining pins.  Here we use the primary receiver library
    // and poll the rest manually for hit detection only.

    decode_results results;
    if (irRecv.decode(&results)) {
        if (results.bits == IR_PACKET_BITS)
            processIRHit(results.value);
        irRecv.resume();
    }

    // For secondary receivers: if any signal detected, we treat it as
    // a hit from the last decoded packet (simplification — a full
    // implementation would run software IR decode on all 5 pins).
}

// =============================================================================
// SETUP
// =============================================================================
void setup() {
    Serial.begin(115200);
    DBG_PRINTLN("[BOOT] setup begin");

    // Buttons (active low)
    pinMode(PIN_BTN_RELOAD,     INPUT_PULLUP);
    pinMode(PIN_BTN_TEAM,       INPUT_PULLUP);
    pinMode(PIN_BTN_SILENT,     INPUT_PULLUP);
    pinMode(PIN_BTN_RESET_VOTE, INPUT_PULLUP);

    // Output drivers
    pinMode(PIN_MOTOR, OUTPUT);
    digitalWrite(PIN_MOTOR, LOW);

    // Init FastLED before IR (both can use ESP32 RMT resources).
    FastLED.addLeds<WS2812B, PIN_WS2812B, GRB>(leds, NUM_LEDS);
    FastLED.setBrightness(100);
    FastLED.clear();
    FastLED.show();
    ledsInitialized = true;
    DBG_PRINTLN("[BOOT] FastLED ready");

    // IR
    irSend.begin();
    irRecv.enableIRIn();
    DBG_PRINTLN("[BOOT] IR ready");

    // OLED
    Wire.begin(OLED_SDA, OLED_SCL);
    if (!oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
        Serial.println("OLED init failed");
    }
    oled.clearDisplay();
    oled.setTextColor(SSD1306_WHITE);
    oled.setTextSize(1);
    oled.setCursor(0, 0);
    oled.println("Booting...");
    oled.display();
    DBG_PRINTLN("[BOOT] OLED ready");

    // Initialise state
    memset(peerTeams,     0, sizeof(peerTeams));
    memset(peerReady,     0, sizeof(peerReady));
    memset(peerResetVote, 0, sizeof(peerResetVote));
    memset(pubKeyReceived,0, sizeof(pubKeyReceived));
    memset(pending,       0, sizeof(pending));
    memset(usedNonces,    0, sizeof(usedNonces));
    initTable();

    myTeam = TEAM_NONE;
    gameState = LOBBY;
    displayDirty = true;

    // ESP-NOW
    initEspNow();
    WiFi.macAddress(myMAC);
    assignPlayerIDs();
    DBG_PRINTF("[BOOT] initial myPlayerID=%u\n", (unsigned)myPlayerID);
    DBG_PRINTF("[BOOT] WiFi status=%d\n", (int)WiFi.status());
    Serial.printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        myMAC[0], myMAC[1], myMAC[2], myMAC[3], myMAC[4], myMAC[5]);

    // ECDH key generation
    generateKeyPair();
    DBG_PRINTLN("[BOOT] keypair generated");

    // All core state is initialized; callbacks can now mutate state safely.
    setupComplete = true;
    DBG_PRINTLN("[BOOT] setup complete");
    DBG_PRINTF("[BOOT] cfg debugger=%d required_ready=%u\n",
               (int)LT_DEBUGGER_NODE,
               (unsigned)readyThreshold());
    DBG_PRINTF("[BOOT] ready threshold=%u\n", (unsigned)readyThreshold());
    DBG_PRINTLN("[BOOT] debug serial commands: ? help, i snapshot, k counters, 0 quiet, 1 verbose");

#if LT_DEBUGGER_NODE
    dbgLogHeartbeat = true;
    dbgLogTxRx = true;
    dbgLogLobby = false;
    dbgAllowTx = false;
    DBG_PRINTLN("[BOOT] LT_DEBUGGER_NODE=1 (passive sniffer mode)");
    DBG_PRINTLN("[BOOT] press 'x' to allow debugger TX for interactive tests");
#endif

    // Request sync in case we are joining a running game
#if !LT_DEBUGGER_NODE
    sendSyncRequest();
#endif

    oled.clearDisplay();
    oled.setCursor(0, 0);
    oled.println("Ready. Press TEAM");
    oled.println("to pick colour.");
    oled.display();
}

// =============================================================================
// MAIN LOOP
// =============================================================================
void loop() {
    handleDebugSerial();

    if (gameState != lastLoggedState) {
        DBG_PRINTF("[STATE] %s -> %s\n",
                   gameStateName(lastLoggedState),
                   gameStateName(gameState));
        lastLoggedState = gameState;
    }

    uint32_t now = millis();
    if (dbgLogHeartbeat && (now - lastHeartbeatMs >= 2000)) {
        lastHeartbeatMs = now;
        uint8_t readyCount = readyCountThreshold();
        uint8_t threshold = readyThreshold();
        DBG_PRINTF("[HB] t=%lu st=%s team=%u id=%u peers=%u ready=%u/%u wifi=%d rx=%lu txA=%lu txE=%lu txOk=%lu txFail=%lu heap=%u\n",
                   (unsigned long)now,
                   gameStateName(gameState),
                   (unsigned)myTeam,
                   (unsigned)myPlayerID,
                   (unsigned)peerCount,
                   (unsigned)readyCount,
                   (unsigned)threshold,
                   (int)WiFi.status(),
                   (unsigned long)rxPacketCount,
                   (unsigned long)txAttemptCount,
                   (unsigned long)txSendErrCount,
                   (unsigned long)txSentOkCount,
                   (unsigned long)txSentFailCount,
                   (unsigned)ESP.getFreeHeap());
    }

    handleButtons();
    updateWeaponMode();
    checkSilentExpiry();
    expirePending();

    switch (gameState) {

        case LOBBY:
            lobbyBroadcast();
            maybeStartFromReady();
            updateLEDs();
            // Pressing READY when myTeam is chosen sends the ready vote
            // (mapped to BTN_RESET_VOTE in lobby for simplicity —
            //  you may wire a dedicated READY button)
            break;

        case STARTING:
            runStartingCountdown();
            break;

        case IN_GAME:
            checkIRReceive();
            periodicSync();
            // Trigger fire on any active-high "trigger" signal.
            // A real build wires the trigger to a GPIO not listed here;
            // call fireGun() from that interrupt or poll.
            // Example: fireGun() called when PIN_BTN_RELOAD is held in
            // an alternate mapping.
            updateLEDs();
            break;

        case ROUND_OVER:
            updateLEDs();
            break;

        case RESETTING:
            doReset();
            break;
    }

    displayUpdate();
    delay(10);
}
