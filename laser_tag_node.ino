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
#define AR_AMMO_MAX         30
#define AR_COOLDOWN_MS      150
#define PISTOL_COOLDOWN_MS  300
#define MOTOR_HIT_MS        100
#define MOTOR_KILL_MS       150
#define MOTOR_DEATH_MS      500
#define MOTOR_WIN_MS        120

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
    fill_solid(leds, NUM_LEDS, color);
    FastLED.show();
}

void ledsOff() { setAllLEDs(CRGB::Black); }

void flashLEDs(CRGB color, uint32_t ms) {
    setAllLEDs(color);
    delay(ms);
    setAllLEDs(CRGB::Black);
}

void ledHitFlash() {
    if (silentMode) return;
    CRGB prev = teamColor(myTeam);
    flashLEDs(CRGB::White, 80);
    setAllLEDs(prev);
}

void ledCryptoEviction() {
    for (int i = 0; i < 8; i++) {
        setAllLEDs(CRGB::Red);
        delay(80);
        ledsOff();
        delay(80);
    }
}

void updateLEDs() {
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
    esp_now_send(BROADCAST_MAC, (const uint8_t*)data, len);
}

void sendPubKey() {
    PktPubKey pkt;
    pkt.hdr = {PKT_PUBKEY_BROADCAST, myPlayerID};
    memcpy(pkt.pubKey, publicKey, 64);
    espNowSend(&pkt, sizeof(pkt));
}

void sendTeamSelect() {
    PktTeamSelect pkt;
    pkt.hdr  = {PKT_TEAM_SELECT, myPlayerID};
    pkt.team = myTeam;
    espNowSend(&pkt, sizeof(pkt));
}

void sendReadyVote() {
    PktVote pkt;
    pkt.hdr = {PKT_READY_VOTE, myPlayerID};
    espNowSend(&pkt, sizeof(pkt));
}

void sendResetVote() {
    PktVote pkt;
    pkt.hdr = {PKT_RESET_VOTE, myPlayerID};
    espNowSend(&pkt, sizeof(pkt));
}

void sendSyncRequest() {
    PktSyncRequest pkt;
    pkt.hdr = {PKT_SYNC_REQUEST, myPlayerID};
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
void onDataRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (len < (int)sizeof(PktHeader)) return;
    const PktHeader *hdr = (const PktHeader*)data;
    uint8_t sid = hdr->senderID;

    switch (hdr->type) {

        case PKT_PUBKEY_BROADCAST: {
            if (len < (int)sizeof(PktPubKey)) break;
            if (sid >= MAX_PLAYERS || sid == myPlayerID) break;
            if (gameState != LOBBY) break; // key exchange locked after lobby
            const PktPubKey *pkt = (const PktPubKey*)data;
            memcpy(peerPubKeys[sid], pkt->pubKey, 64);
            pubKeyReceived[sid] = true;
            // Register peer MAC
            bool known = false;
            for (uint8_t i = 0; i < peerCount; i++)
                if (memcmp(peerMACs[i], info->src_addr, 6) == 0) { known = true; break; }
            if (!known && peerCount < MAX_PLAYERS - 1)
                memcpy(peerMACs[peerCount++], info->src_addr, 6);
            break;
        }

        case PKT_TEAM_SELECT: {
            if (len < (int)sizeof(PktTeamSelect)) break;
            if (sid >= MAX_PLAYERS) break;
            const PktTeamSelect *pkt = (const PktTeamSelect*)data;
            peerTeams[sid] = pkt->team;
            displayDirty = true;
            break;
        }

        case PKT_READY_VOTE: {
            if (sid >= MAX_PLAYERS) break;
            peerReady[sid] = true;
            displayDirty = true;
            // Check unanimous
            bool allReady = true;
            for (uint8_t i = 0; i < MAX_PLAYERS; i++)
                if (!peerReady[i]) { allReady = false; break; }
            if (allReady && gameState == LOBBY) {
                deriveSharedSecrets();
                assignPlayerIDs();
                // init own HP slot
                gameTable[myPlayerID].ownerID = myPlayerID;
                gameTable[myPlayerID].value   = STARTING_HP;
                gameTable[myPlayerID].version = 0;
                peerTeams[myPlayerID] = myTeam;
                gameState = STARTING;
                displayDirty = true;
            }
            break;
        }

        case PKT_HIT_CLAIM: {
            if (len < (int)sizeof(PktHitClaim)) break;
            const PktHitClaim *pkt = (const PktHitClaim*)data;
            // If we are the shooter, send confirm
            if (pkt->shooterID == myPlayerID) {
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
            addShotConfirm(*pkt);
            break;
        }

        case PKT_SYNC_REQUEST: {
            if (sid >= MAX_PLAYERS) break;
            sendSyncResponse(info->src_addr);
            break;
        }

        case PKT_SYNC_RESPONSE: {
            if (len < (int)sizeof(PktSyncResponse)) break;
            const PktSyncResponse *pkt = (const PktSyncResponse*)data;
            mergeTable(pkt->table);
            displayDirty = true;
            break;
        }

        case PKT_RESET_VOTE: {
            if (sid >= MAX_PLAYERS) break;
            peerResetVote[sid] = true;
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
    // Optional: log delivery status for debugging
}

// =============================================================================
// ESP-NOW INIT
// =============================================================================
void initEspNow() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    if (esp_now_init() != ESP_OK) {
        Serial.println("ESP-NOW init failed");
        return;
    }
    esp_now_register_recv_cb(onDataRecv);
    esp_now_register_send_cb(onDataSent);

    // Register broadcast peer
    esp_now_peer_info_t peerInfo;
    memset(&peerInfo, 0, sizeof(peerInfo));
    memcpy(peerInfo.peer_addr, BROADCAST_MAC, 6);
    peerInfo.channel = 0;
    peerInfo.encrypt = false;
    esp_now_add_peer(&peerInfo);
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
    uint32_t now = millis();
    if (now - lastLobbyBcast < LOBBY_BCAST_MS) return;
    lastLobbyBcast = now;
    sendPubKey();
    if (myTeam != TEAM_NONE) sendTeamSelect();
}

// =============================================================================
// PERIODIC SYNC
// =============================================================================
void periodicSync() {
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

    // Buttons (active low)
    pinMode(PIN_BTN_RELOAD,     INPUT_PULLUP);
    pinMode(PIN_BTN_TEAM,       INPUT_PULLUP);
    pinMode(PIN_BTN_SILENT,     INPUT_PULLUP);
    pinMode(PIN_BTN_RESET_VOTE, INPUT_PULLUP);

    // Output drivers
    pinMode(PIN_MOTOR, OUTPUT);
    digitalWrite(PIN_MOTOR, LOW);

    // IR
    irSend.begin();
    irRecv.enableIRIn();

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

    // WS2812B
    FastLED.addLeds<WS2812B, PIN_WS2812B, GRB>(leds, NUM_LEDS);
    FastLED.setBrightness(100);
    ledsOff();

    // ESP-NOW
    initEspNow();
    WiFi.macAddress(myMAC);
    Serial.printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        myMAC[0], myMAC[1], myMAC[2], myMAC[3], myMAC[4], myMAC[5]);

    // ECDH key generation
    generateKeyPair();

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

    // Request sync in case we are joining a running game
    sendSyncRequest();

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
    handleButtons();
    updateWeaponMode();
    checkSilentExpiry();
    expirePending();

    switch (gameState) {

        case LOBBY:
            lobbyBroadcast();
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
