// app protocol over UDP transport
// handshake, version, peerid, encrypted req/resp

#include "common.h"
#include "udp_transport.h"
#include "overlay.h"

#include <arpa/inet.h>
#include <string.h>
#include <time.h>

static uint8_t g_my_peer_id[OVERLAY_PEER_ID_LEN];

static overlay_session_t g_sessions[OVERLAY_MAX_SESSIONS_HARD];
static pthread_mutex_t   g_ov_mutex = PTHREAD_MUTEX_INITIALIZER;

static overlay_connected_cb_t g_cb_connected = NULL;
static overlay_request_cb_t   g_cb_request   = NULL;
static overlay_response_cb_t  g_cb_response  = NULL;
static overlay_pex_cb_t       g_cb_pex       = NULL;
static overlay_closed_cb_t    g_cb_closed    = NULL;

static const uint8_t overlay_aead_ad[] = "B2NYnYxC";

#define OVERLAY_FRAME_REST_MAX \
    (1u + OVERLAY_CRYPTO_CTR_LEN + OVERLAY_RESP_HDR + \
     OVERLAY_CHUNK_MAX + OVERLAY_CRYPTO_MAC_LEN)

static int overlay_calculate_backoff(int attempts)
{
    int backoff = OVERLAY_RECONNECT_BACKOFF_BASE;
    for (int i = 1; i < attempts && backoff < OVERLAY_RECONNECT_BACKOFF_MAX; i++) {
        backoff *= OVERLAY_RECONNECT_BACKOFF_BASE;
    }
    return backoff > OVERLAY_RECONNECT_BACKOFF_MAX ? 
           OVERLAY_RECONNECT_BACKOFF_MAX : backoff;
}

static void overlay_queue_pending_msg(overlay_session_t *s, 
                                      const uint8_t *msg, 
                                      size_t len,
                                      uint8_t type)
{
    if (!s || s->pending_count >= OVERLAY_PENDING_MSG_MAX) return;
    
    for (int i = 0; i < OVERLAY_PENDING_MSG_MAX; i++) {
        if (!s->pending_queue[i].used) {
            if (len > sizeof(s->pending_queue[i].data)) {
                net_log("msg too big for queue: %zu bytes", len);
                return;
            }
            memcpy(s->pending_queue[i].data, msg, len);
            s->pending_queue[i].len = len;
            s->pending_queue[i].queued_at = time(NULL);
            s->pending_queue[i].type = type;
            s->pending_queue[i].used = true;
            s->pending_count++;
            return;
        }
    }
}

static void overlay_flush_pending_msgs(overlay_session_t *s)
{
    if (!s || s->utp_conn_id < 0) return;
    
    for (int i = 0; i < OVERLAY_PENDING_MSG_MAX; i++) {
        if (s->pending_queue[i].used) {
            if (udp_transport_write(s->utp_conn_id, 
                             s->pending_queue[i].data, 
                             s->pending_queue[i].len) > 0) {
        net_log("resent message type 0x%02X after reconnect", 
                       s->pending_queue[i].type);
            }
            s->pending_queue[i].used = false;
            s->pending_count--;
        }
    }
}

static void overlay_clear_pending_msgs(overlay_session_t *s)
{
    if (!s) return;
    for (int i = 0; i < OVERLAY_PENDING_MSG_MAX; i++) {
        s->pending_queue[i].used = false;
    }
    s->pending_count = 0;
}

static size_t overlay_build_msg(uint8_t *out, size_t out_size,
                                 uint8_t type,
                                 const uint8_t *payload, size_t plen)
{
    if (plen > (SIZE_MAX - 5)) return 0;
    
    size_t total = 5 + plen;
    if (total > out_size) return 0;

    uint64_t rest_len_64 = 1ULL + (uint64_t)plen;
    if (rest_len_64 > UINT32_MAX) return 0;
    
    uint32_t rest_len = (uint32_t)rest_len_64;
    out[0] = (uint8_t)(rest_len >> 24);
    out[1] = (uint8_t)(rest_len >> 16);
    out[2] = (uint8_t)(rest_len >>  8);
    out[3] = (uint8_t)(rest_len);
    out[4] = type;

    if (plen > 0 && payload)
        memcpy(out + 5, payload, plen);
    return total;
}

static overlay_session_t *overlay_alloc_session(void)
{
    for (int i = 0; i < overlay_max_sessions; i++) {
        if (g_sessions[i].state == OVERLAY_SESS_FREE) {
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].utp_conn_id = -1;
            g_sessions[i].reconnect_attempts = 0;
            g_sessions[i].reconnect_after = 0;
            g_sessions[i].pending_count = 0;
            g_sessions[i].auto_reconnect = false;
            return &g_sessions[i];
        }
    }
    return NULL;
}

static int overlay_session_index(const overlay_session_t *s)
{
    return (int)(s - g_sessions);
}

static overlay_session_t *overlay_find_by_utp_locked(int utp_conn_id)
{
    for (int i = 0; i < overlay_max_sessions; i++) {
        if (g_sessions[i].state != OVERLAY_SESS_FREE &&
            g_sessions[i].utp_conn_id == utp_conn_id)
            return &g_sessions[i];
    }
    return NULL;
}

static void overlay_close_session_locked(overlay_session_t *s)
{
    if (!s || s->state == OVERLAY_SESS_FREE ||
        s->state == OVERLAY_SESS_CLOSING)
        return;

    int cid = s->utp_conn_id;
    s->utp_conn_id = -1;
    
    if (s->auto_reconnect && s->peer_id_valid && 
        s->reconnect_attempts < OVERLAY_RECONNECT_MAX_ATTEMPTS) {
        s->state = OVERLAY_SESS_RECONNECTING;
        int backoff = overlay_calculate_backoff(s->reconnect_attempts);
        s->reconnect_after = time(NULL) + backoff;
        s->reconnect_attempts++;
        net_log("session %d entering reconnect (attempt %d, backoff %ds)",
                overlay_session_index(s), s->reconnect_attempts, backoff);
        if (cid >= 0) udp_transport_close(cid);
        return;
    }
    
    if (cid >= 0) udp_transport_close(cid);
    p2p_secure_wipe(s->session_key, sizeof(s->session_key));
    overlay_clear_pending_msgs(s);
    s->state = OVERLAY_SESS_FREE;
}

static void overlay_store64_le(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t overlay_load64_le(const uint8_t in[8])
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= ((uint64_t)in[i] << (8 * i));
    return v;
}

static bool overlay_make_nonce(const uint8_t sender_id[OVERLAY_PEER_ID_LEN],
                               uint64_t counter,
                               uint8_t nonce[CRYPTO_NONCE_LEN])
{
    if (!sender_id || !nonce) return false;
    memset(nonce, 0, CRYPTO_NONCE_LEN);
    memcpy(nonce, sender_id, CRYPTO_NONCE_PREFIX_LEN);
    overlay_store64_le(nonce + CRYPTO_NONCE_PREFIX_LEN, counter);
    return true;
}

static bool overlay_accept_counter(overlay_session_t *s, uint64_t counter)
{
    if (!s) return false;
    if (s->rx_nonce_valid && counter <= s->rx_last_nonce)
        return false;

    s->rx_last_nonce = counter;
    s->rx_nonce_valid = true;
    return true;
}

static bool overlay_derive_session_key(overlay_session_t *s)
{
    if (!s || !s->peer_id_valid) return false;

    const uint8_t *a = g_my_peer_id;
    const uint8_t *b = s->peer_id;
    if (memcmp(a, b, OVERLAY_PEER_ID_LEN) > 0) {
        a = s->peer_id;
        b = g_my_peer_id;
    }

    if (!crypto_derive_context_key("overlay-modules-v2",
                                   a, OVERLAY_PEER_ID_LEN,
                                   b, OVERLAY_PEER_ID_LEN,
                                   s->session_key))
        return false;
    if (!crypto_random_u64(&s->tx_nonce))
        s->tx_nonce = ((uint64_t)time(NULL) << 32) ^
                      (uint64_t)(uint32_t)s->utp_conn_id;
    s->crypto_ready = true;
    return true;
}

static size_t overlay_build_encrypted_msg(overlay_session_t *s,
                                          uint8_t *out, size_t out_size,
                                          uint8_t type,
                                          const uint8_t *payload,
                                          size_t plen)
{
    if (!s || !s->crypto_ready || !out) return 0;
    if (plen > OVERLAY_CHUNK_MAX + OVERLAY_RESP_HDR) return 0;

    // validate enc_len before calculating total
    if (plen > (SIZE_MAX - OVERLAY_CRYPTO_CTR_LEN - OVERLAY_CRYPTO_MAC_LEN)) return 0;
    
    size_t enc_len = OVERLAY_CRYPTO_CTR_LEN + plen + OVERLAY_CRYPTO_MAC_LEN;
    
    // validate total before using
    if (enc_len > (SIZE_MAX - 5)) return 0;
    
    size_t total = 5 + enc_len;
    if (total > out_size) return 0;

    // validate rest_len fits in uint32_t
    uint64_t rest_len_64 = 1ULL + (uint64_t)enc_len;
    if (rest_len_64 > UINT32_MAX) return 0;
    
    uint32_t rest_len = (uint32_t)rest_len_64;
    out[0] = (uint8_t)(rest_len >> 24);
    out[1] = (uint8_t)(rest_len >> 16);
    out[2] = (uint8_t)(rest_len >>  8);
    out[3] = (uint8_t)(rest_len);
    out[4] = type;

    uint64_t counter = ++s->tx_nonce;
    uint8_t nonce[CRYPTO_NONCE_LEN];
    overlay_store64_le(out + 5, counter);
    if (!overlay_make_nonce(g_my_peer_id, counter, nonce))
        return 0;

    crypto_aead_lock(out + 5 + OVERLAY_CRYPTO_CTR_LEN,
                     out + 5 + OVERLAY_CRYPTO_CTR_LEN + plen,
                     s->session_key, nonce,
                     overlay_aead_ad, sizeof(overlay_aead_ad) - 1,
                     payload, plen);
    p2p_secure_wipe(nonce, sizeof(nonce));
    return total;
}

static bool overlay_decrypt_payload(overlay_session_t *s,
                                    uint8_t type,
                                    uint8_t *payload,
                                    uint32_t plen,
                                    uint8_t *plain,
                                    uint32_t *plain_len)
{
    (void)type;
    if (!s || !payload || !plain || !plain_len || !s->crypto_ready)
        return false;
    if (plen < OVERLAY_CRYPTO_OVERHEAD) return false;

    uint64_t counter = overlay_load64_le(payload);
    size_t clen = (size_t)plen - OVERLAY_CRYPTO_OVERHEAD;
    uint8_t nonce[CRYPTO_NONCE_LEN];
    if (!overlay_make_nonce(s->peer_id, counter, nonce))
        return false;

    const uint8_t *cipher = payload + OVERLAY_CRYPTO_CTR_LEN;
    const uint8_t *mac = cipher + clen;
    int rc = crypto_aead_unlock(plain, mac, s->session_key, nonce,
                                overlay_aead_ad,
                                sizeof(overlay_aead_ad) - 1,
                                cipher, clen);
    p2p_secure_wipe(nonce, sizeof(nonce));
    if (rc != 0) return false;
    if (!overlay_accept_counter(s, counter)) {
        net_log("replay counter=%llu last=%llu",
                (unsigned long long)counter,
                (unsigned long long)s->rx_last_nonce);
        p2p_secure_wipe(plain, clen);
        return false;
    }
    *plain_len = (uint32_t)clen;
    return true;
}

static bool overlay_send_handshake(int utp_conn_id)
{
    uint8_t payload[OVERLAY_HS_PAYLOAD];
    memcpy(payload, OVERLAY_MAGIC, OVERLAY_MAGIC_LEN);
    payload[6] = (uint8_t)(OVERLAY_VERSION >> 8);
    payload[7] = (uint8_t)(OVERLAY_VERSION & 0xFF);
    memcpy(payload + 8, g_my_peer_id, OVERLAY_PEER_ID_LEN);

    uint8_t msg[5 + OVERLAY_HS_PAYLOAD];
    size_t  mlen = overlay_build_msg(msg, sizeof(msg),
                                      OVERLAY_MSG_HANDSHAKE,
                                      payload, sizeof(payload));
    if (!mlen) return false;
    if (udp_transport_write(utp_conn_id, msg, mlen) <= 0) {
        char utp_status[256];
        udp_transport_describe_connection(utp_conn_id,
                                        utp_status, sizeof(utp_status));
        net_log("hs failed: udp=%d st=\"%s\" last=\"%s\"",
                utp_conn_id, utp_status, udp_transport_last_error());
        return false;
    }
    return true;
}

static void overlay_process_message(overlay_session_t *s,
                                     uint8_t type,
                                     uint8_t *payload,
                                     uint32_t plen)
{
    int sid = overlay_session_index(s);

    switch (type) {
    case OVERLAY_MSG_HANDSHAKE: {
        if (plen < (uint32_t)OVERLAY_HS_PAYLOAD) {
            net_log("short handshake session %d", sid);
            overlay_close_session_locked(s);
            return;
        }

        if (memcmp(payload, OVERLAY_MAGIC, OVERLAY_MAGIC_LEN) != 0) {
            net_log("bad magic session %d", sid);
            overlay_close_session_locked(s);
            return;
        }

        uint16_t ver = ((uint16_t)payload[6] << 8) | payload[7];
        if (ver != OVERLAY_VERSION) {
            net_log("incompatible version 0x%04X session %d", ver, sid);
            overlay_close_session_locked(s);
            return;
        }

        memcpy(s->peer_id, payload + 8, OVERLAY_PEER_ID_LEN);
        s->peer_id_valid = true;
        if (!overlay_derive_session_key(s)) {
            net_log("could not derive key session %d", sid);
            overlay_close_session_locked(s);
            return;
        }

        if (!s->is_outbound) {
            if (!overlay_send_handshake(s->utp_conn_id)) {
                net_log("handshake response failed session %d udp=%d last=\"%s\"",
                        sid, s->utp_conn_id, udp_transport_last_error());
                overlay_close_session_locked(s);
                return;
            }
        }

        s->state = OVERLAY_SESS_ESTABLISHED;
        net_log("session %d aead peer %02x%02x%02x...",
                sid, s->peer_id[0], s->peer_id[1], s->peer_id[2]);
        
        s->reconnect_attempts = 0;
        s->last_keepalive_sent = time(NULL);
        s->last_keepalive_recv = time(NULL);
        
        if (s->pending_count > 0) {
            overlay_flush_pending_msgs(s);
        }

        if (g_cb_connected) {
            uint8_t peer_id_copy[OVERLAY_PEER_ID_LEN];
            memcpy(peer_id_copy, s->peer_id, OVERLAY_PEER_ID_LEN);
            int sid_copy = sid;
            
            pthread_mutex_unlock(&g_ov_mutex);
            g_cb_connected(sid_copy, peer_id_copy);
            pthread_mutex_lock(&g_ov_mutex);
            
            if (sid >= OVERLAY_MAX_SESSIONS || g_sessions[sid].state != OVERLAY_SESS_ESTABLISHED) {
                net_log("session invalidated during connected callback session %d", sid);
                return;
            }
        }
        break;
    }

    case OVERLAY_MSG_REQUEST: {
        if (s->state != OVERLAY_SESS_ESTABLISHED) return;
        if (plen < (uint32_t)OVERLAY_REQ_PAYLOAD) {
            net_log("short request session %d", sid);
            return;
        }
        uint8_t infohash[OVERLAY_INFOHASH_LEN];
        memcpy(infohash, payload, OVERLAY_INFOHASH_LEN);
        uint32_t offset = ((uint32_t)payload[20] << 24)
                        | ((uint32_t)payload[21] << 16)
                        | ((uint32_t)payload[22] <<  8)
                        |  (uint32_t)payload[23];
        uint32_t length = ((uint32_t)payload[24] << 24)
                        | ((uint32_t)payload[25] << 16)
                        | ((uint32_t)payload[26] <<  8)
                        |  (uint32_t)payload[27];

        if (g_cb_request) {
            uint8_t infohash_copy[OVERLAY_INFOHASH_LEN];
            memcpy(infohash_copy, infohash, OVERLAY_INFOHASH_LEN);
            int sid_copy = sid;
            
            pthread_mutex_unlock(&g_ov_mutex);
            g_cb_request(sid_copy, infohash_copy, offset, length);
            pthread_mutex_lock(&g_ov_mutex);
        }
        break;
    }

    case OVERLAY_MSG_RESPONSE: {
        if (s->state != OVERLAY_SESS_ESTABLISHED) return;
        if (plen < (uint32_t)OVERLAY_RESP_HDR) {
            net_log("short response session %d", sid);
            return;
        }
        uint8_t infohash[OVERLAY_INFOHASH_LEN];
        memcpy(infohash, payload, OVERLAY_INFOHASH_LEN);
        uint32_t offset = ((uint32_t)payload[20] << 24)
                        | ((uint32_t)payload[21] << 16)
                        | ((uint32_t)payload[22] <<  8)
                        |  (uint32_t)payload[23];
        const uint8_t *data = payload + OVERLAY_RESP_HDR;
        size_t data_len = plen - OVERLAY_RESP_HDR;

        if (g_cb_response) {
            uint8_t infohash_copy[OVERLAY_INFOHASH_LEN];
            memcpy(infohash_copy, infohash, OVERLAY_INFOHASH_LEN);
            uint8_t *data_copy = NULL;
            if (data_len > 0) {
                data_copy = (uint8_t *)malloc(data_len);
                if (data_copy) memcpy(data_copy, data, data_len);
            }
            int sid_copy = sid;
            
            pthread_mutex_unlock(&g_ov_mutex);
            if (data_copy || data_len == 0) {
                g_cb_response(sid_copy, infohash_copy, offset, data_copy, data_len);
            }
            pthread_mutex_lock(&g_ov_mutex);
            
            if (data_copy) {
                p2p_secure_wipe(data_copy, data_len);
                free(data_copy);
            }
        }
        break;
    }

    case OVERLAY_MSG_PEX: {
        if (s->state != OVERLAY_SESS_ESTABLISHED) return;
        if (plen < 2) return;

        uint16_t count = ((uint16_t)payload[0] << 8) | payload[1];
        if (count > OVERLAY_PEX_MAX) count = OVERLAY_PEX_MAX;

        size_t expected = 2 + (size_t)count * OVERLAY_PEX_ENTRY_SIZE;
        
        if (expected > UINT32_MAX || plen < (uint32_t)expected) {
            net_log("pex truncated session %d expected=%zu plen=%u", sid, expected, plen);
            return;
        }

        struct sockaddr_in peers[OVERLAY_PEX_MAX];
        uint8_t node_ids[OVERLAY_PEX_MAX][OVERLAY_PEER_ID_LEN];

        for (int i = 0; i < count; i++) {
            size_t entry_offset = 2 + (size_t)i * OVERLAY_PEX_ENTRY_SIZE;
            if (entry_offset + OVERLAY_PEX_ENTRY_SIZE > plen) {
                net_log("pex entry bounds session %d", sid);
                return;
            }
            
            const uint8_t *e = payload + entry_offset;
            memset(&peers[i], 0, sizeof(peers[i]));
            peers[i].sin_family = AF_INET;
            memcpy(&peers[i].sin_addr.s_addr, e,     4);
            memcpy(&peers[i].sin_port,         e + 4, 2);
            memcpy(node_ids[i],                e + 6, 20);
        }

        if (g_cb_pex) {
            struct sockaddr_in peers_copy[OVERLAY_PEX_MAX];
            uint8_t node_ids_copy[OVERLAY_PEX_MAX][OVERLAY_PEER_ID_LEN];
            memcpy(peers_copy, peers, sizeof(struct sockaddr_in) * count);
            memcpy(node_ids_copy, node_ids, OVERLAY_PEER_ID_LEN * count);
            int sid_copy = sid;
            int count_copy = count;
            
            pthread_mutex_unlock(&g_ov_mutex);
            g_cb_pex(sid_copy, peers_copy,
                     (const uint8_t (*)[OVERLAY_PEER_ID_LEN])node_ids_copy,
                     count_copy);
            pthread_mutex_lock(&g_ov_mutex);
        }
        break;
    }

    case OVERLAY_MSG_KEEPALIVE: {
        s->last_keepalive_recv = time(NULL);
        net_log("keepalive received session %d", sid);
        break;
    }

    default:
        net_log("unknown type 0x%02X session %d", type, sid);
        break;
    }
}

static void overlay_drain_session(overlay_session_t *s)
{
    while (s->rbuf_len >= 5) {
        uint32_t rest_len = ((uint32_t)s->rbuf[0] << 24)
                          | ((uint32_t)s->rbuf[1] << 16)
                          | ((uint32_t)s->rbuf[2] <<  8)
                          |  (uint32_t)s->rbuf[3];

        if (rest_len == 0 || rest_len > (uint32_t)OVERLAY_FRAME_REST_MAX) {
            net_log("invalid frame rest=%u state=%d session=%d closing",
                    rest_len, (int)s->state, overlay_session_index(s));
            overlay_close_session_locked(s);
            return;
        }

        size_t total = 4 + rest_len;
        
        if (total > sizeof(s->rbuf)) {
            net_log("frame exceeds buffer capacity total=%zu max=%zu session=%d closing",
                    total, sizeof(s->rbuf), overlay_session_index(s));
            overlay_close_session_locked(s);
            return;
        }
        
        if (s->rbuf_len < total) break;

        uint8_t type    = s->rbuf[4];
        uint8_t *payload = s->rbuf + 5;
        uint32_t plen   = rest_len - 1;

        if (s->state == OVERLAY_SESS_HANDSHAKING &&
            (type != OVERLAY_MSG_HANDSHAKE ||
             rest_len != (uint32_t)(1 + OVERLAY_HS_PAYLOAD))) {
            net_log("first frame is not handshake type=0x%02X rest=%u session=%d closing",
                    type, rest_len, overlay_session_index(s));
            overlay_close_session_locked(s);
            return;
        }

        if (s->state == OVERLAY_SESS_ESTABLISHED &&
            type != OVERLAY_MSG_REQUEST &&
            type != OVERLAY_MSG_RESPONSE &&
            type != OVERLAY_MSG_PEX &&
            type != OVERLAY_MSG_KEEPALIVE) {
            net_log("invalid type 0x%02X session %d closing",
                    type, overlay_session_index(s));
            overlay_close_session_locked(s);
            return;
        }

        s->last_activity = time(NULL);
        if (type == OVERLAY_MSG_HANDSHAKE) {
            overlay_process_message(s, type, payload, plen);
        } else {
            uint8_t plain[OVERLAY_CHUNK_MAX + OVERLAY_RESP_HDR + 64];
            uint32_t plain_len = 0;
            if (!overlay_decrypt_payload(s, type, payload, plen,
                                         plain, &plain_len)) {
                net_log("invalid aead or replay session %d closing",
                        overlay_session_index(s));
                overlay_close_session_locked(s);
                return;
            }
            overlay_process_message(s, type, plain, plain_len);
            p2p_secure_wipe(plain, sizeof(plain));
        }

        memmove(s->rbuf, s->rbuf + total, s->rbuf_len - total);
        s->rbuf_len -= total;
    }
}

static void overlay_udp_connected(int conn_id)
{
    struct sockaddr_in peer;
    if (udp_transport_get_peer_addr(conn_id, &peer) != 0) {
        udp_transport_close(conn_id);
        return;
    }
    overlay_on_accept(conn_id, peer);
}

static void overlay_udp_data(int conn_id, const uint8_t *data, size_t len)
{
    if (!data || !len) return;

    pthread_mutex_lock(&g_ov_mutex);
    overlay_session_t *s = overlay_find_by_utp_locked(conn_id);
    if (!s || s->state == OVERLAY_SESS_CLOSING ||
        len > sizeof(s->rbuf) - s->rbuf_len) {
        if (s) {
            net_log("overlay receive buffer overflow session=%d len=%zu",
                    overlay_session_index(s), len);
            overlay_close_session_locked(s);
        }
        pthread_mutex_unlock(&g_ov_mutex);
        return;
    }

    memcpy(s->rbuf + s->rbuf_len, data, len);
    s->rbuf_len += len;
    overlay_drain_session(s);
    pthread_mutex_unlock(&g_ov_mutex);
}

static void overlay_udp_closed(int conn_id)
{
    overlay_on_close(conn_id);
}

void overlay_init(const uint8_t my_peer_id[OVERLAY_PEER_ID_LEN])
{
    pthread_mutex_lock(&g_ov_mutex);
    memcpy(g_my_peer_id, my_peer_id, OVERLAY_PEER_ID_LEN);
    memset(g_sessions, 0, sizeof(g_sessions));
    pthread_mutex_unlock(&g_ov_mutex);
    udp_transport_set_callbacks(overlay_udp_connected,
                                overlay_udp_data,
                                overlay_udp_closed);
}

void overlay_set_callbacks(overlay_connected_cb_t on_connected,
                            overlay_request_cb_t   on_request,
                            overlay_response_cb_t  on_response,
                            overlay_pex_cb_t       on_pex,
                            overlay_closed_cb_t    on_closed)
{
    g_cb_connected = on_connected;
    g_cb_request   = on_request;
    g_cb_response  = on_response;
    g_cb_pex       = on_pex;
    g_cb_closed    = on_closed;
}

void overlay_shutdown(void)
{
    pthread_mutex_lock(&g_ov_mutex);
    for (int i = 0; i < overlay_max_sessions; i++) {
        overlay_session_t *s = &g_sessions[i];
        overlay_close_session_locked(s);
    }
    pthread_mutex_unlock(&g_ov_mutex);
}

int overlay_connect(struct sockaddr_in peer_addr)
{
    pthread_mutex_lock(&g_ov_mutex);
    
    for (int i = 0; i < overlay_max_sessions; i++) {
        overlay_session_t *s = &g_sessions[i];
        if (s->state != OVERLAY_SESS_FREE &&
            s->peer_addr.sin_addr.s_addr == peer_addr.sin_addr.s_addr &&
            s->peer_addr.sin_port == peer_addr.sin_port) {
            pthread_mutex_unlock(&g_ov_mutex);
            net_log("existing session %d for %s:%d",
                    i, inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
            return i;
        }
    }
    
    overlay_session_t *s = overlay_alloc_session();
    if (!s) {
        pthread_mutex_unlock(&g_ov_mutex);
        net_log("could not open session to %s:%d table full",
                inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
        return -1;
    }

    int udp_id = udp_transport_connect(&peer_addr, NULL, NULL, NULL);
    if (udp_id < 0) {
        pthread_mutex_unlock(&g_ov_mutex);
        net_log("udp_connect failed %s:%d: %s",
                inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port),
                udp_transport_last_error());
        return -1;
    }

    s->state         = OVERLAY_SESS_HANDSHAKING;
    s->utp_conn_id   = udp_id;
    s->is_outbound   = true;
    s->peer_addr     = peer_addr;
    s->last_activity = time(NULL);
    s->auto_reconnect = true;

    int sid = overlay_session_index(s);
    pthread_mutex_unlock(&g_ov_mutex);

    net_log("connecting %s:%d session=%d udp=%d (auto-reconnect)",
            inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port),
            sid, udp_id);
    return sid;
}

void overlay_close(int sess_id)
{
    if (sess_id < 0 || sess_id >= overlay_max_sessions) return;
    pthread_mutex_lock(&g_ov_mutex);
    overlay_session_t *s = &g_sessions[sess_id];
    overlay_close_session_locked(s);
    pthread_mutex_unlock(&g_ov_mutex);
}

bool overlay_send_request(int sess_id,
                           const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                           uint32_t offset,
                           uint32_t length)
{
    if (sess_id < 0 || sess_id >= overlay_max_sessions) return false;

    uint8_t payload[OVERLAY_REQ_PAYLOAD];
    memcpy(payload, infohash, OVERLAY_INFOHASH_LEN);
    payload[20] = (uint8_t)(offset >> 24);
    payload[21] = (uint8_t)(offset >> 16);
    payload[22] = (uint8_t)(offset >>  8);
    payload[23] = (uint8_t)(offset);
    payload[24] = (uint8_t)(length >> 24);
    payload[25] = (uint8_t)(length >> 16);
    payload[26] = (uint8_t)(length >>  8);
    payload[27] = (uint8_t)(length);

    uint8_t msg[5 + OVERLAY_REQ_PAYLOAD + OVERLAY_CRYPTO_OVERHEAD];
    pthread_mutex_lock(&g_ov_mutex);
    overlay_session_t *s = &g_sessions[sess_id];
    
    if (s->state != OVERLAY_SESS_ESTABLISHED) {
        size_t mlen = overlay_build_encrypted_msg(s, msg, sizeof(msg),
                                                  OVERLAY_MSG_REQUEST,
                                                  payload, sizeof(payload));
        if (mlen > 0 && s->auto_reconnect) {
            overlay_queue_pending_msg(s, msg, mlen, OVERLAY_MSG_REQUEST);
            pthread_mutex_unlock(&g_ov_mutex);
            return true;
        }
        pthread_mutex_unlock(&g_ov_mutex);
        return false;
    }
    
    int utp_id = s->utp_conn_id;
    size_t mlen = overlay_build_encrypted_msg(s, msg, sizeof(msg),
                                              OVERLAY_MSG_REQUEST,
                                              payload, sizeof(payload));
    pthread_mutex_unlock(&g_ov_mutex);

    if (!mlen) return false;
    return udp_transport_write(utp_id, msg, mlen) > 0;
}

bool overlay_send_response(int sess_id,
                            const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                            uint32_t offset,
                            const uint8_t *data,
                            size_t data_len)
{
    if (sess_id < 0 || sess_id >= overlay_max_sessions) return false;
    if (data_len > OVERLAY_CHUNK_MAX) data_len = OVERLAY_CHUNK_MAX;

    if (data_len > (SIZE_MAX - OVERLAY_RESP_HDR)) return false;
    
    size_t plen = OVERLAY_RESP_HDR + data_len;
    uint8_t *payload = (uint8_t *)malloc(plen);
    if (!payload) return false;

    memcpy(payload, infohash, OVERLAY_INFOHASH_LEN);
    payload[20] = (uint8_t)(offset >> 24);
    payload[21] = (uint8_t)(offset >> 16);
    payload[22] = (uint8_t)(offset >>  8);
    payload[23] = (uint8_t)(offset);
    if (data && data_len > 0)
        memcpy(payload + OVERLAY_RESP_HDR, data, data_len);

    if (plen > (SIZE_MAX - 5 - OVERLAY_CRYPTO_OVERHEAD)) {
        free(payload);
        return false;
    }
    
    uint8_t *msg = (uint8_t *)malloc(5 + plen + OVERLAY_CRYPTO_OVERHEAD);
    bool ok = false;
    if (msg) {
        pthread_mutex_lock(&g_ov_mutex);
        overlay_session_t *s = &g_sessions[sess_id];
        int utp_id = s->utp_conn_id;
        size_t mlen = overlay_build_encrypted_msg(s, msg,
                                                   5 + plen + OVERLAY_CRYPTO_OVERHEAD,
                                                   OVERLAY_MSG_RESPONSE,
                                                   payload, plen);
        pthread_mutex_unlock(&g_ov_mutex);
        if (mlen > 0) {
            ok = udp_transport_write(utp_id, msg, mlen) > 0;
        }
        free(msg);
    }
    free(payload);
    return ok;
}

bool overlay_send_pex(int sess_id,
                       const struct sockaddr_in *peers,
                       const uint8_t (*node_ids)[OVERLAY_PEER_ID_LEN],
                       int count)
{
    if (sess_id < 0 || sess_id >= overlay_max_sessions) return false;
    if (count < 0 || count > OVERLAY_PEX_MAX) count = OVERLAY_PEX_MAX;

    // validate multiplication before use
    if ((size_t)count > ((SIZE_MAX - 2) / OVERLAY_PEX_ENTRY_SIZE)) return false;
    
    size_t plen = 2 + (size_t)count * OVERLAY_PEX_ENTRY_SIZE;
    uint8_t *payload = (uint8_t *)malloc(plen);
    if (!payload) return false;

    payload[0] = (uint8_t)(count >> 8);
    payload[1] = (uint8_t)(count);

    for (int i = 0; i < count; i++) {
        uint8_t *e = payload + 2 + i * OVERLAY_PEX_ENTRY_SIZE;
        memcpy(e,      &peers[i].sin_addr.s_addr, 4);
        memcpy(e + 4,  &peers[i].sin_port,         2);
        memcpy(e + 6,  node_ids[i],                20);
    }

    if (plen > (SIZE_MAX - 5 - OVERLAY_CRYPTO_OVERHEAD)) {
        free(payload);
        return false;
    }
    
    uint8_t *msg = (uint8_t *)malloc(5 + plen + OVERLAY_CRYPTO_OVERHEAD);
    bool ok = false;
    if (msg) {
        pthread_mutex_lock(&g_ov_mutex);
        overlay_session_t *s = &g_sessions[sess_id];
        int utp_id = s->utp_conn_id;
        size_t mlen = overlay_build_encrypted_msg(s, msg,
                                                   5 + plen + OVERLAY_CRYPTO_OVERHEAD,
                                                   OVERLAY_MSG_PEX,
                                                   payload, plen);
        pthread_mutex_unlock(&g_ov_mutex);
        if (mlen > 0) {
            ok = udp_transport_write(utp_id, msg, mlen) > 0;
        }
        free(msg);
    }
    free(payload);
    return ok;
}

void overlay_on_data(int utp_conn_id)
{
    pthread_mutex_lock(&g_ov_mutex);
    overlay_session_t *s = overlay_find_by_utp_locked(utp_conn_id);
    if (!s || s->state == OVERLAY_SESS_CLOSING) {
        pthread_mutex_unlock(&g_ov_mutex);
        return;
    }
    overlay_drain_session(s);
    pthread_mutex_unlock(&g_ov_mutex);
}

void overlay_on_accept(int utp_conn_id, struct sockaddr_in peer)
{
    pthread_mutex_lock(&g_ov_mutex);

    overlay_session_t *existing = overlay_find_by_utp_locked(utp_conn_id);
    if (existing) {
        if (existing->is_outbound && existing->state == OVERLAY_SESS_HANDSHAKING) {
            pthread_mutex_unlock(&g_ov_mutex);
            if (!overlay_send_handshake(utp_conn_id)) {
                net_log("outbound hs failed udp=%d last=\"%s\"",
                        utp_conn_id, udp_transport_last_error());
            }
            return;
        }
        pthread_mutex_unlock(&g_ov_mutex);
        return;
    }

    overlay_session_t *s = overlay_alloc_session();
    if (!s) {
        pthread_mutex_unlock(&g_ov_mutex);
        udp_transport_close(utp_conn_id);
        return;
    }

    memset(s, 0, sizeof(*s));
    s->state         = OVERLAY_SESS_HANDSHAKING;
    s->utp_conn_id   = utp_conn_id;
    s->is_outbound   = false;
    s->peer_addr     = peer;
    s->last_activity = time(NULL);

    pthread_mutex_unlock(&g_ov_mutex);
}

void overlay_on_close(int utp_conn_id)
{
    pthread_mutex_lock(&g_ov_mutex);
    overlay_session_t *s = overlay_find_by_utp_locked(utp_conn_id);
    if (!s) {
        pthread_mutex_unlock(&g_ov_mutex);
        return;
    }
    int sid = overlay_session_index(s);
    s->utp_conn_id = -1;
    bool notify = true;
    if (s->auto_reconnect && s->peer_id_valid &&
        s->reconnect_attempts < OVERLAY_RECONNECT_MAX_ATTEMPTS) {
        int backoff = overlay_calculate_backoff(s->reconnect_attempts + 1);
        s->state = OVERLAY_SESS_RECONNECTING;
        s->reconnect_after = time(NULL) + backoff;
        s->reconnect_attempts++;
        notify = false;
    } else {
        p2p_secure_wipe(s->session_key, sizeof(s->session_key));
        overlay_clear_pending_msgs(s);
        s->state = OVERLAY_SESS_FREE;
    }
    pthread_mutex_unlock(&g_ov_mutex);

    if (notify && g_cb_closed) {
        int sid_copy = sid;
        g_cb_closed(sid_copy);
    }
}

void overlay_tick(void)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&g_ov_mutex);

    for (int i = 0; i < overlay_max_sessions; i++) {
        overlay_session_t *s = &g_sessions[i];
        if (s->state == OVERLAY_SESS_FREE) continue;

        if (s->state == OVERLAY_SESS_RECONNECTING) {
            if (now >= s->reconnect_after) {
                if (s->reconnect_attempts >= OVERLAY_RECONNECT_MAX_ATTEMPTS) {
                    net_log("max reconnect attempts reached session %d, freeing", i);
                    overlay_clear_pending_msgs(s);
                    p2p_secure_wipe(s->session_key, sizeof(s->session_key));
                    s->state = OVERLAY_SESS_FREE;
                    
                    if (g_cb_closed) {
                        int sid_copy = i;
                        pthread_mutex_unlock(&g_ov_mutex);
                        g_cb_closed(sid_copy);
                        pthread_mutex_lock(&g_ov_mutex);
                    }
                    continue;
                }
                
                net_log("attempting reconnect session %d (attempt %d/%d)",
                        i, s->reconnect_attempts + 1, OVERLAY_RECONNECT_MAX_ATTEMPTS);
                
                struct sockaddr_in peer_addr_copy = s->peer_addr;
                pthread_mutex_unlock(&g_ov_mutex);
                int udp_id = udp_transport_connect(&peer_addr_copy, NULL, NULL, NULL);
                pthread_mutex_lock(&g_ov_mutex);
                
                if (i >= overlay_max_sessions || g_sessions[i].state != OVERLAY_SESS_RECONNECTING) {
                    net_log("session invalidated during reconnect session %d", i);
                    if (udp_id >= 0) {
                        pthread_mutex_unlock(&g_ov_mutex);
                        udp_transport_close(udp_id);
                        pthread_mutex_lock(&g_ov_mutex);
                    }
                    continue;
                }
                
                if (udp_id >= 0) {
                    s->utp_conn_id = udp_id;
                    s->state = OVERLAY_SESS_HANDSHAKING;
                    s->last_activity = now;
                    s->reconnect_attempts++;
                    net_log("reconnect started session %d udp=%d", i, udp_id);
                } else {
                    int backoff = overlay_calculate_backoff(s->reconnect_attempts);
                    s->reconnect_after = now + backoff;
                    s->reconnect_attempts++;
                    net_log("reconnect failed session %d, retry in %ds (attempt %d/%d)",
                            i, backoff, s->reconnect_attempts, OVERLAY_RECONNECT_MAX_ATTEMPTS);
                }
            }
            continue;
        }

        if (s->state == OVERLAY_SESS_HANDSHAKING &&
            (now - s->last_activity) > OVERLAY_HS_TIMEOUT) {
            char peer_str[INET_ADDRSTRLEN + 8];
            char utp_status[256];
            inet_ntop(AF_INET, &s->peer_addr.sin_addr,
                      peer_str, INET_ADDRSTRLEN);
            snprintf(peer_str + strlen(peer_str),
                     sizeof(peer_str) - strlen(peer_str),
                     ":%d", ntohs(s->peer_addr.sin_port));
            udp_transport_describe_connection(s->utp_conn_id,
                                        utp_status, sizeof(utp_status));
            net_log("handshake timeout session %d peer=%s udp=%d out=%d age=%lds rbuf=%zu "
                    "crypto=%d peer_id=%d st=\"%s\" ult=\"%s\"",
                    i, peer_str, s->utp_conn_id, s->is_outbound ? 1 : 0,
                    (long)(now - s->last_activity), s->rbuf_len,
                    s->crypto_ready ? 1 : 0, s->peer_id_valid ? 1 : 0,
                    utp_status, udp_transport_last_error());
            overlay_close_session_locked(s);
            continue;
        }

        if (s->state == OVERLAY_SESS_ESTABLISHED &&
            (now - s->last_keepalive_sent) > OVERLAY_KEEPALIVE_INTERVAL) {
            uint8_t msg[5 + OVERLAY_CRYPTO_OVERHEAD];
            size_t mlen = overlay_build_encrypted_msg(s, msg, sizeof(msg),
                                                       OVERLAY_MSG_KEEPALIVE,
                                                       NULL, 0);
            if (mlen > 0 && udp_transport_write(s->utp_conn_id, msg, mlen) > 0) {
                s->last_keepalive_sent = now;
            }
        }

        if (s->state == OVERLAY_SESS_ESTABLISHED &&
            (now - s->last_keepalive_recv) > OVERLAY_SESSION_TIMEOUT) {
            net_log("session %d inactive (no keepalive), closing", i);
            overlay_close_session_locked(s);
            continue;
        }
    }

    pthread_mutex_unlock(&g_ov_mutex);
}

int overlay_find_by_utp(int utp_conn_id)
{
    pthread_mutex_lock(&g_ov_mutex);
    overlay_session_t *s = overlay_find_by_utp_locked(utp_conn_id);
    int sid = s ? overlay_session_index(s) : -1;
    pthread_mutex_unlock(&g_ov_mutex);
    return sid;
}

int overlay_session_count(void)
{
    int count = 0;
    pthread_mutex_lock(&g_ov_mutex);
    for (int i = 0; i < overlay_max_sessions; i++) {
        if (g_sessions[i].state == OVERLAY_SESS_ESTABLISHED)
            count++;
    }
    pthread_mutex_unlock(&g_ov_mutex);
    return count;
}

void overlay_dump_sessions(void)
{
    pthread_mutex_lock(&g_ov_mutex);
    printf("=== active sessions ===\n");
    for (int i = 0; i < overlay_max_sessions; i++) {
        overlay_session_t *s = &g_sessions[i];
        if (s->state == OVERLAY_SESS_FREE) continue;

        char peer_str[INET_ADDRSTRLEN + 8];
        inet_ntop(AF_INET, &s->peer_addr.sin_addr, peer_str, INET_ADDRSTRLEN);
        snprintf(peer_str + strlen(peer_str),
                 sizeof(peer_str) - strlen(peer_str),
                 ":%d", ntohs(s->peer_addr.sin_port));

        const char *st = "?";
        switch (s->state) {
        case OVERLAY_SESS_HANDSHAKING: st = "HANDSHAKING"; break;
        case OVERLAY_SESS_ESTABLISHED: st = "ESTABLISHED"; break;
        case OVERLAY_SESS_CLOSING:     st = "CLOSING";     break;
        case OVERLAY_SESS_RECONNECTING: st = "RECONNECTING"; break;
        default: break;
        }

        char pid_hex[9] = "????????";
        if (s->peer_id_valid)
            snprintf(pid_hex, sizeof(pid_hex), "%02x%02x%02x%02x",
                     s->peer_id[0], s->peer_id[1], s->peer_id[2], s->peer_id[3]);

        printf(" [%2d] %-22s %-13s peer=%s... udp=%d recon=%d/%d pend=%d auto=%d\n",
               i, peer_str, st, pid_hex, s->utp_conn_id,
               s->reconnect_attempts, OVERLAY_RECONNECT_MAX_ATTEMPTS,
               s->pending_count, s->auto_reconnect ? 1 : 0);
    }
    pthread_mutex_unlock(&g_ov_mutex);
}

bool overlay_send_keepalive(int sess_id)
{
    if (sess_id < 0 || sess_id >= overlay_max_sessions) return false;
    
    pthread_mutex_lock(&g_ov_mutex);
    overlay_session_t *s = &g_sessions[sess_id];
    
    if (s->state != OVERLAY_SESS_ESTABLISHED || s->utp_conn_id < 0) {
        pthread_mutex_unlock(&g_ov_mutex);
        return false;
    }
    
    uint8_t msg[5 + OVERLAY_CRYPTO_OVERHEAD];
    size_t mlen = overlay_build_encrypted_msg(s, msg, sizeof(msg),
                                               OVERLAY_MSG_KEEPALIVE,
                                               NULL, 0);
    int utp_id = s->utp_conn_id;
    pthread_mutex_unlock(&g_ov_mutex);
    
    if (mlen == 0) return false;
    
    bool ok = udp_transport_write(utp_id, msg, mlen) > 0;
    if (ok) {
        pthread_mutex_lock(&g_ov_mutex);
        if (sess_id < OVERLAY_MAX_SESSIONS && g_sessions[sess_id].state == OVERLAY_SESS_ESTABLISHED)
            g_sessions[sess_id].last_keepalive_sent = time(NULL);
        pthread_mutex_unlock(&g_ov_mutex);
    }
    return ok;
}

void overlay_set_auto_reconnect(int sess_id, bool auto_reconnect)
{
    if (sess_id < 0 || sess_id >= overlay_max_sessions) return;
    
    pthread_mutex_lock(&g_ov_mutex);
    overlay_session_t *s = &g_sessions[sess_id];
    if (s->state != OVERLAY_SESS_FREE) {
        s->auto_reconnect = auto_reconnect;
        net_log("session %d auto_reconnect=%d", sess_id, auto_reconnect ? 1 : 0);
    }
    pthread_mutex_unlock(&g_ov_mutex);
}

int overlay_find_by_peer_id(const uint8_t peer_id[OVERLAY_PEER_ID_LEN])
{
    if (!peer_id) return -1;
    
    pthread_mutex_lock(&g_ov_mutex);
    for (int i = 0; i < overlay_max_sessions; i++) {
        overlay_session_t *s = &g_sessions[i];
        if (s->state != OVERLAY_SESS_FREE && s->peer_id_valid &&
            memcmp(s->peer_id, peer_id, OVERLAY_PEER_ID_LEN) == 0) {
            pthread_mutex_unlock(&g_ov_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&g_ov_mutex);
    return -1;
}

static bool net_id_to_sockaddr(node_id_t net_id, struct sockaddr_in *addr)
{
    if (!addr) return false;
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    memcpy(&addr->sin_addr.s_addr, net_id.id, 4);
    memcpy(&addr->sin_port, net_id.id + 4, 2);
    return true;
}

int overlay_find_by_net_id(node_id_t net_id)
{
    struct sockaddr_in target_addr;
    if (!net_id_to_sockaddr(net_id, &target_addr))
        return -1;
        
    pthread_mutex_lock(&g_ov_mutex);
    for (int i = 0; i < overlay_max_sessions; i++) {
        overlay_session_t *s = &g_sessions[i];
        if (s->state != OVERLAY_SESS_FREE &&
            s->peer_addr.sin_addr.s_addr == target_addr.sin_addr.s_addr &&
            s->peer_addr.sin_port == target_addr.sin_port) {
            pthread_mutex_unlock(&g_ov_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&g_ov_mutex);
    return -1;
}
