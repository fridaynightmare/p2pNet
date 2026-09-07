#include "common.h"
#include "udp_transport.h"
#include "overlay.h"
#include "guard.h"
#include "watchdog.h"

// whatever
#define C_RESET  "\033[0m"
#define C_RED    "\033[31m"
#define C_GREEN  "\033[32m"
#define C_BLUE   "\033[34m"
#define C_YELLOW "\033[33m"



static node_id_t random_key_as(node_id_t exclude)
{
    node_id_t choices[AS_MAX];
    int count = 0;
    for (int i = 0; i < as_count; i++)
        if (!id_equal(as[i]->id.id, exclude.id))
            choices[count++] = as[i]->id;
    if (count == 0) { node_id_t z = {{0}}; return z; }
    return choices[crypto_random_below((uint32_t)count)];
}

static bool ssl_read_exact(P2PConn *ssl, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        int n = p2p_conn_read(ssl, buf + off, (int)(len - off));
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

#define HS_HELLO_OFF CRYPTO_HS_SALT_LEN
#define HS_PORT_OFF  (HS_HELLO_OFF + 1)
#define HS_PUB_OFF   (HS_PORT_OFF + 2)
#define HS_X_OFF     (HS_PUB_OFF + CRYPTO_PUBKEY_LEN)
#define HS_POW_OFF   (HS_X_OFF + CRYPTO_X25519_KEY_LEN)
#define HS_PROOF_OFF (HS_POW_OFF + CRYPTO_POW_NONCE_LEN)

#define HR_SALT_OFF  1
#define HR_PUB_OFF   (HR_SALT_OFF + CRYPTO_HS_SALT_LEN)
#define HR_X_OFF     (HR_PUB_OFF + CRYPTO_PUBKEY_LEN)
#define HR_PROOF_OFF (HR_X_OFF + CRYPTO_X25519_KEY_LEN)

static const char hs_req_proof_label[] = "p2p-hs-req-v1";
static const char hs_resp_proof_label[] = "p2p-hs-resp-v1";

static bool inbound_rate_allow(const struct sockaddr_in *addr)
{
    if (!addr) return false;
    time_t now = time(NULL);
    uint32_t ip = addr->sin_addr.s_addr;
    int free_slot = -1;
    int oldest_slot = 0;

    pthread_mutex_lock(&inbound_rate_mutex);
    for (int i = 0; i < INBOUND_RATE_MAX; i++) {
        if (!inbound_rate_table[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (inbound_rate_table[i].window_start <
            inbound_rate_table[oldest_slot].window_start)
            oldest_slot = i;
        if (inbound_rate_table[i].ip_addr != ip)
            continue;
        if (now - inbound_rate_table[i].window_start >
            INBOUND_HANDSHAKE_WINDOW) {
            inbound_rate_table[i].window_start = now;
            inbound_rate_table[i].handshake_count = 1;
            pthread_mutex_unlock(&inbound_rate_mutex);
            return true;
        }
        if (inbound_rate_table[i].handshake_count >=
            INBOUND_HANDSHAKE_RATE_MAX) {
            pthread_mutex_unlock(&inbound_rate_mutex);
            return false;
        }
        inbound_rate_table[i].handshake_count++;
        pthread_mutex_unlock(&inbound_rate_mutex);
        return true;
    }

    int slot = (free_slot >= 0) ? free_slot : oldest_slot;
    inbound_rate_table[slot].used = true;
    inbound_rate_table[slot].ip_addr = ip;
    inbound_rate_table[slot].handshake_count = 1;
    inbound_rate_table[slot].window_start = now;
    pthread_mutex_unlock(&inbound_rate_mutex);
    return true;
}

static int leading_zero_bits(const uint8_t digest[32])
{
    int bits = 0;
    for (int i = 0; i < 32; i++) {
        if (digest[i] == 0) {
            bits += 8;
            continue;
        }
        uint8_t b = digest[i];
        for (int j = 7; j >= 0; j--) {
            if ((b & (1u << j)) != 0) return bits;
            bits++;
        }
    }
    return bits;
}

static bool handshake_pow_ok(const uint8_t hs[HPV_HS_SIGNED_LEN])
{
    uint8_t digest[32];
    sha256(hs, HS_PROOF_OFF, digest);
    return leading_zero_bits(digest) >= P2P_HANDSHAKE_POW_BITS;
}

static bool solve_handshake_pow(uint8_t hs[HPV_HS_SIGNED_LEN])
{
    uint64_t nonce = 0;
    if (!crypto_random_u64(&nonce)) {
        return false;
    }
    while (1) {
        for (int i = 0; i < CRYPTO_POW_NONCE_LEN; i++)
            hs[HS_POW_OFF + i] = (uint8_t)(nonce >> (8 * i));
        if (handshake_pow_ok(hs)) return true;
        nonce++;
    }
}

static void handle_packet(active_node_t *node, uint8_t *pkt, size_t len)
{
    if (len <= CRYPTO_SEAL_OVERHEAD) {
        del_connection_reason(node->id, 1, "short-pkt");
        return;
    }

    uint8_t plain[HPV_PKT_MAX];
    size_t payload_len = 0;
    if (!node->session_key_valid) {
        del_connection_reason(node->id, 1, "no-pfs");
        return;
    }
    if (!crypto_open_with_key(pkt, len, plain, &payload_len, node->session_key)) {
        del_connection_reason(node->id, 1, "bad-crypto");
        return;
    }

    if (!node->trust_verified) {
        if (!node->pubkey_valid) {
            del_connection_reason(node->id, 1, "no-identity");
            return;
        }
        node->trust_verified = true;
    }

    if (payload_len < 1) return;
    uint8_t   cmd      = plain[0];
    uint8_t  *data     = plain + 1;
    size_t    data_len = payload_len - 1;
    node_id_t src_id   = node->id;

    switch (cmd) {
    case M_FORW_JOIN: {
        if (data_len < 7) return;
        uint8_t   hops = data[0];
        node_id_t target_id;
        memcpy(target_id.id, data+1, 6);
        if (is_self_node(target_id)) break;
        if (p2p_guard_under_pressure() && as_count >= n0) {
            add_passive(target_id.id, 1);
            break;
        }
        hops++;
        if (hops >= arwl && as_count < nb) {
            connect_to_reason(target_id, H_NEIGHBOR_LO, "forw-join");
        } else {
            add_passive(target_id.id, 1);
            if (hops < mrwl) {
                node_id_t next = random_key_as(target_id);
                if (next.id[0] != 0) {
                    uint8_t fwd[8];
                    fwd[0] = M_FORW_JOIN; fwd[1] = hops;
                    memcpy(fwd+2, target_id.id, 6);
                    sndpkt(next, fwd, 8);
                }
            }
        }
        break;
    }

    case M_SHUFFLE: {
        int n_ids = (int)(data_len / 6);
        if (n_ids <= 0) break;
        for (int i = 0; i < n_ids; i++) {
            node_id_t tmp;
            memcpy(tmp.id, data + i*6, 6);
            if (!id_equal(tmp.id, src_id.id) && !is_self_node(tmp) &&
                p2p_node_id_is_public(tmp))
                add_passive(tmp.id, 1);
        }
        if (n_ids > 1) {
            node_id_t next = random_key_as(src_id);
            if (next.id[0] != 0) {
                size_t fwd_len = (size_t)(n_ids-1) * 6;
                uint8_t *fwd = malloc(1 + fwd_len);
                if (fwd) {
                    fwd[0] = M_SHUFFLE;
                    memcpy(fwd+1, data, fwd_len);
                    sndpkt(next, fwd, 1 + fwd_len);
                    free(fwd);
                }
            }
        }
        break;
    }

    case M_BROADCAST: {
        if (data_len < 2) return;
        uint8_t ttl     = data[0];
        uint8_t subtype = data[1];
        if (subtype == P2P_BC_SUBTYPE) {
            if (flood(src_id, subtype, data+2, data_len-2, ttl))
                p2p_handle_gossip_message(src_id, data+2, data_len-2, ttl);
        } else {
            flood(src_id, subtype, data+2, data_len-2, ttl);
        }
        break;
    }

    case M_WHISPER: {
        if (data_len < 1) return;
        uint8_t sub_type = data[0];
        if (sub_type >= M_DHT_PING && sub_type <= M_DHT_STORE_ACK)
            handle_dht_packet(src_id, sub_type, data+1, data_len-1);
        break;
    }

    case M_DISCONNECT:

        del_connection_reason(src_id, 1, "disconnect-peer");
        break;

    case M_PING: {
        uint8_t pong[25];
        pong[0] = M_PONG;
        uint64_t echo_ts = 0;
        if (data_len >= 8) {
            echo_ts  = ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48)
                     | ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32)
                     | ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16)
                     | ((uint64_t)data[6] <<  8) | ((uint64_t)data[7]      );
        }
        pong[1] = (uint8_t)(echo_ts >> 56); pong[2] = (uint8_t)(echo_ts >> 48);
        pong[3] = (uint8_t)(echo_ts >> 40); pong[4] = (uint8_t)(echo_ts >> 32);
        pong[5] = (uint8_t)(echo_ts >> 24); pong[6] = (uint8_t)(echo_ts >> 16);
        pong[7] = (uint8_t)(echo_ts >>  8); pong[8] = (uint8_t)(echo_ts      );
        uint64_t now_ts = (uint64_t)time(NULL);
        pong[ 9] = (uint8_t)(now_ts >> 56); pong[10] = (uint8_t)(now_ts >> 48);
        pong[11] = (uint8_t)(now_ts >> 40); pong[12] = (uint8_t)(now_ts >> 32);
        pong[13] = (uint8_t)(now_ts >> 24); pong[14] = (uint8_t)(now_ts >> 16);
        pong[15] = (uint8_t)(now_ts >>  8); pong[16] = (uint8_t)(now_ts      );
        uint64_t start_ts = (uint64_t)my_node_start_time;
        pong[17] = (uint8_t)(start_ts >> 56); pong[18] = (uint8_t)(start_ts >> 48);
        pong[19] = (uint8_t)(start_ts >> 40); pong[20] = (uint8_t)(start_ts >> 32);
        pong[21] = (uint8_t)(start_ts >> 24); pong[22] = (uint8_t)(start_ts >> 16);
        pong[23] = (uint8_t)(start_ts >>  8); pong[24] = (uint8_t)(start_ts      );
        sndpkt(src_id, pong, sizeof(pong));
        break;
    }

    case M_PONG: {
        /* FIXED: Strict PONG validation - only accept defined lengths */
        if (data_len != 8 && data_len != 16 && data_len != 24) {
            net_log("Invalid PONG length %zu from %s, expected 8, 16, or 24",
                    data_len, id2str(src_id));
            return;
        }
        
        if (data_len >= 8) {
            uint64_t ts = 0;
            ts |= ((uint64_t)data[0] << 56); ts |= ((uint64_t)data[1] << 48);
            ts |= ((uint64_t)data[2] << 40); ts |= ((uint64_t)data[3] << 32);
            ts |= ((uint64_t)data[4] << 24); ts |= ((uint64_t)data[5] << 16);
            ts |= ((uint64_t)data[6] <<  8); ts |= ((uint64_t)data[7]      );
            for (int i = 0; i < as_count; i++) {
                if (!id_equal(as[i]->id.id, src_id.id)) continue;
                if (data_len == 8) {
                    as[i]->peer_start_time = (time_t)ts;
                } else if (data_len >= 16) {
                    uint64_t echo_ts_val = ts;
                    uint64_t peer_now = 0;
                    peer_now |= ((uint64_t)data[ 8] << 56); peer_now |= ((uint64_t)data[ 9] << 48);
                    peer_now |= ((uint64_t)data[10] << 40); peer_now |= ((uint64_t)data[11] << 32);
                    peer_now |= ((uint64_t)data[12] << 24); peer_now |= ((uint64_t)data[13] << 16);
                    peer_now |= ((uint64_t)data[14] <<  8); peer_now |= ((uint64_t)data[15]      );
                    if (data_len == 24) {
                        uint64_t peer_start = 0;
                        peer_start |= ((uint64_t)data[16] << 56); peer_start |= ((uint64_t)data[17] << 48);
                        peer_start |= ((uint64_t)data[18] << 40); peer_start |= ((uint64_t)data[19] << 32);
                        peer_start |= ((uint64_t)data[20] << 24); peer_start |= ((uint64_t)data[21] << 16);
                        peer_start |= ((uint64_t)data[22] <<  8); peer_start |= ((uint64_t)data[23]      );
                        if (peer_start > 0)
                            as[i]->peer_start_time = (time_t)peer_start;
                    }
                    if (peer_now > 0 && echo_ts_val > 0) {
                        int64_t local_recv  = (int64_t)time(NULL);
                        int64_t rtt_secs    = local_recv - (int64_t)echo_ts_val;
                        if (rtt_secs >= 0 && rtt_secs <= 30) {
                            int64_t midpoint    = (int64_t)echo_ts_val + rtt_secs / 2;
                            int64_t new_offset  = midpoint - (int64_t)peer_now;
                            p2p_clock_add_sample(i, new_offset);
                        }
                    }
                }
                break;
            }
        }
        break;
    }

    case M_ARCH: {
        if (data_len == 0 || data_len >= sizeof(as[0]->peer_arch)) break;
        for (int i = 0; i < as_count; i++) {
            if (id_equal(as[i]->id.id, src_id.id)) {
                memcpy(as[i]->peer_arch, data, data_len);
                as[i]->peer_arch[data_len] = '\0';
                break;
            }
        }
        break;
    }

    default:
        if (cmd >= M_DHT_PING && cmd <= M_DHT_STORE_ACK)
            handle_dht_packet(src_id, cmd, data, data_len);
        break;
    }
}

static void process_node_packets(active_node_t *node)
{
    while (node->rbuf_len > 0) {
        uint16_t pkt_len;
        size_t   head_size;
        node_id_t cur_id = node->id;

        if (node->rbuf[0] != 0) {
            pkt_len   = node->rbuf[0];
            head_size = 1;
        } else {
            if (node->rbuf_len < 3) break;
            uint16_t nlen;
            memcpy(&nlen, node->rbuf+1, 2);
            pkt_len   = ntohs(nlen);
            head_size = 3;
        }

        if (pkt_len == 0 || pkt_len > HPV_PKT_WIRE_MAX) {
            net_log("weird frame from %s, closing i guess",
                    id2str(cur_id));
            del_connection_reason(cur_id, 1, "bad-frame");
            return;
        }

        if (node->rbuf_len < head_size + pkt_len) break;

        handle_packet(node, node->rbuf + head_size, pkt_len);

        bool still_active = false;
        for (int i = 0; i < as_count; i++) {
            if (id_equal(as[i]->id.id, cur_id.id)) {
                node = as[i];
                still_active = true;
                break;
            }
        }
        if (!still_active) return;

        size_t consumed = head_size + pkt_len;
        memmove(node->rbuf, node->rbuf + consumed, node->rbuf_len - consumed);
        node->rbuf_len -= consumed;
    }
}

static void set_socket_opts(int fd)
{
    int opt = 1;
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE, &opt, sizeof(opt));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,  &opt, sizeof(opt));
#ifdef TCP_KEEPIDLE
    { int v = 10; setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &v, sizeof(v)); }
#endif
#ifdef TCP_KEEPINTVL
    { int v =  5; setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &v, sizeof(v)); }
#endif
#ifdef TCP_KEEPCNT
    { int v =  3; setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &v, sizeof(v)); }
#endif
}

static void add_connection(int fd, node_id_t id, P2PConn *ssl,
                            const uint8_t *peer_pubkey,
                            const uint8_t *session_key,
                            const char *reason)
{
    const char *origin = (reason && reason[0]) ? reason : "dunno";
    if (is_self_node(id)) {
        if (ssl) { p2p_conn_shutdown(ssl); p2p_conn_free(ssl); }
        close(fd);
        return;
    }
    if (!p2p_node_id_is_public(id)) {
        if (ssl) { p2p_conn_shutdown(ssl); p2p_conn_free(ssl); }
        close(fd);
        return;
    }
    if (!peer_pubkey) {
        if (ssl) { p2p_conn_shutdown(ssl); p2p_conn_free(ssl); }
        close(fd);
        return;
    }
    if (!session_key) {
        if (ssl) { p2p_conn_shutdown(ssl); p2p_conn_free(ssl); }
        close(fd);
        return;
    }
    dht_id_t peer_identity = dht_id_from_pubkey(peer_pubkey);
    for (int i = 0; i < as_count; i++) {
        if (id_equal(as[i]->id.id, id.id)) {
            remove_passive(id);
            if (ssl) { p2p_conn_shutdown(ssl); p2p_conn_free(ssl); }
            close(fd);
            return;
        }
        if (memcmp(as[i]->dht_id.bytes, peer_identity.bytes,
                   DHT_ID_BYTES) == 0) {
            if (ssl) { p2p_conn_shutdown(ssl); p2p_conn_free(ssl); }
            close(fd);
            return;
        }
    }

    if (as_count >= nb) {
        int victim = (int)crypto_random_below((uint32_t)as_count);
        del_connection_reason(as[victim]->id, 0, "local-prune");
    }

    if (as_count >= AS_MAX) {
        if (ssl) { p2p_conn_shutdown(ssl); p2p_conn_free(ssl); }
        close(fd);
        return;
    }

    active_node_t *node = calloc(1, sizeof(active_node_t));
    if (!node) {
        if (ssl) { p2p_conn_shutdown(ssl); p2p_conn_free(ssl); }
        close(fd);
        return;
    }
    node->fd     = fd;
    node->ssl    = ssl;
    node->id     = id;
    node->dht_id = peer_identity;
    if (!crypto_random_u64(&node->tx_nonce)) {
        free(node);
        if (ssl) { p2p_conn_shutdown(ssl); p2p_conn_free(ssl); }
        close(fd);
        return;
    }

    if (peer_pubkey) {
        memcpy(node->peer_ed25519_pubkey, peer_pubkey, CRYPTO_PUBKEY_LEN);
        node->pubkey_valid = true;
    }
    memcpy(node->session_key, session_key, 32);
    node->session_key_valid = true;
    memset(node->clock_samples, 0, sizeof(node->clock_samples));
    memset(node->clock_sample_seen, 0, sizeof(node->clock_sample_seen));
    node->clock_sample_count  = 0;
    node->clock_sample_head   = 0;
    node->clock_offset_valid  = false;
    snprintf(node->peer_arch, sizeof(node->peer_arch), "Unknown");

    as[as_count++] = node;
    remove_passive(id);

    {
        size_t alen = strlen(my_arch);
        uint8_t arch_pkt[17];
        arch_pkt[0] = M_ARCH;
        memcpy(arch_pkt + 1, my_arch, alen);
        sndpkt(id, arch_pkt, 1 + alen);
    }

    if (epoll_fd >= 0) {
        struct epoll_event ev;
        ev.events   = EPOLLIN;
        ev.data.ptr = node;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
            (void)0;
    }

    dht_node_t dn;
    dn.net_id = id;
    dn.dht_id = node->dht_id;
    dht_routing_table_add(dn);

    dht_send(id, M_DHT_PING, my_dht_id.bytes, DHT_ID_BYTES);
    dht_stats.total_pings_sent++;

    if (dht_bootstrap_pending) {
        dht_bootstrap_pending = false;
        int slot = dht_lookup_alloc(my_dht_id, false);
        if (slot >= 0) {
            dht_lookup_start(slot);
        }
    }

    net_log("ok peer=%s from=%s",
            id2str(id), origin);

}

static void pending_out_remove(node_id_t id)
{
    pthread_mutex_lock(&pending_mutex);
    for (int i = 0; i < pending_out_count; i++) {
        if (id_equal(pending_out[i].id, id.id)) {
            pending_out[i] = pending_out[pending_out_count-1];
            pending_out_count--;
            break;
        }
    }
    pthread_mutex_unlock(&pending_mutex);
}

static bool pending_out_add(node_id_t id)
{
    pthread_mutex_lock(&pending_mutex);
    for (int i = 0; i < pending_out_count; i++) {
        if (id_equal(pending_out[i].id, id.id)) {
            pthread_mutex_unlock(&pending_mutex);
            return false; // yeah it's already there
        }
    }
    if (pending_out_count < CONN_QUEUE_MAX) {
        pending_out[pending_out_count++] = id;
        pthread_mutex_unlock(&pending_mutex);
        return true;
    }
    pthread_mutex_unlock(&pending_mutex);
    return false;
}

static void *conn_worker_thread(void *arg)
{
    (void)arg;
    while (1) {
        pthread_mutex_lock(&conn_mutex);
        while (conn_queue_count == 0 && pool_running)
            pthread_cond_wait(&conn_cond, &conn_mutex);
        if (!pool_running && conn_queue_count == 0) {
            pthread_mutex_unlock(&conn_mutex);
            break;
        }
        conn_job_t job = conn_queue[conn_queue_head];
        conn_queue_head = (conn_queue_head + 1) % CONN_QUEUE_MAX;
        conn_queue_count--;
        pthread_mutex_unlock(&conn_mutex);

        conn_result_t *res = calloc(1, sizeof(conn_result_t));
        if (!res) { if (!job.is_inbound) pending_out_remove(job.target_id); continue; }

        if (job.is_inbound) {
            int fd = job.inbound_fd;
            struct sockaddr_in ca = job.inbound_addr;

            struct timeval rcvto = {5, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));
            set_socket_opts(fd);

            P2PConn *ssl = p2p_conn_wrap_server(fd);
            if (!ssl) {
                close(fd); free(res);
                continue;
            }

            uint8_t hs[HPV_HS_LEN];
            if (!ssl_read_exact(ssl, hs, HPV_HS_LEN)) {
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd); free(res); continue;
            }
            const uint8_t *peer_pubkey = hs + HS_PUB_OFF;
            const uint8_t *peer_x25519 = peer_pubkey + CRYPTO_PUBKEY_LEN;
            const uint8_t *peer_sig = hs + HPV_HS_SIGNED_LEN;
            if (!handshake_pow_ok(hs)) {
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd); free(res); continue;
            }
            if (!crypto_verify(hs, HPV_HS_SIGNED_LEN, peer_sig, peer_pubkey)) {
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd); free(res); continue;
            }
            if (!crypto_group_proof_verify(hs_req_proof_label, hs,
                                           HS_PROOF_OFF,
                                           hs + HS_PROOF_OFF)) {
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd); free(res); continue;
            }
            node_id_t new_id;
            memcpy(new_id.id,     &ca.sin_addr.s_addr, 4);
            memcpy(new_id.id + 4, hs + HS_PORT_OFF,    2);
            if (is_self_node(new_id)) {
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd); free(res); continue;
            }
            if (!p2p_node_id_is_public(new_id)) {
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd); free(res); continue;
            }

            uint8_t hello_type = hs[HS_HELLO_OFF];

            if (as_count >= na) {
                add_passive(new_id.id, 1);

                if (hello_type == H_JOIN && as_count > 0) {
                    uint8_t fwd[8];
                    fwd[0] = M_FORW_JOIN;
                    fwd[1] = 0;
                    memcpy(fwd + 2, new_id.id, 6);
                    for (int k = 0; k < as_count; k++)
                        sndpkt(as[k]->id, fwd, 8);

                }

                uint8_t reject_payload[1 + 6 * 6];
                reject_payload[0] = H_REJECT;
                int sent = 0;

                int ps_want = ps_count < 4 ? ps_count : 4;
                int ps_picked[4];
                int ps_picked_n = 0;
                for (int k = 0; k < ps_want && sent < 6; k++) {
                    int idx = (int)crypto_random_below((uint32_t)ps_count);
                    bool already = false;
                    for (int m = 0; m < ps_picked_n; m++)
                        if (ps_picked[m] == idx) { already = true; break; }
                    if (already) continue;
                    ps_picked[ps_picked_n++] = idx;
                    memcpy(reject_payload + 1 + sent * 6, ps[idx].id.id, 6);
                    sent++;
                }

                int as_picked[6];
                int as_picked_n = 0;
                for (int k = 0; k < as_count && sent < 6; k++) {
                    int idx = (int)crypto_random_below((uint32_t)as_count);
                    bool already = false;
                    for (int m = 0; m < as_picked_n; m++)
                        if (as_picked[m] == idx) { already = true; break; }
                    if (already) continue;
                    as_picked[as_picked_n++] = idx;
                    memcpy(reject_payload + 1 + sent * 6, as[idx]->id.id, 6);
                    sent++;
                }

                if (sent > 0)
                    p2p_conn_write(ssl, reject_payload, 1 + sent * 6);

                net_log("full, %s goes to passive i guess",
                        id2str(new_id));

                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                free(res); continue;
            }

            uint8_t sx_secret[CRYPTO_X25519_KEY_LEN];
            uint8_t sx_pub[CRYPTO_X25519_KEY_LEN];
            uint8_t resp[HPV_HS_RESP_LEN];
            if (!crypto_make_x25519_keypair(sx_secret, sx_pub)) {
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd); free(res); continue;
            }
            resp[0] = H_ACCEPT;
            if (!crypto_random_bytes(resp + HR_SALT_OFF, CRYPTO_HS_SALT_LEN)) {
                memset(sx_secret, 0, sizeof(sx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd); free(res); continue;
            }
            memcpy(resp + HR_PUB_OFF, my_ed25519_pubkey, CRYPTO_PUBKEY_LEN);
            memcpy(resp + HR_X_OFF, sx_pub, CRYPTO_X25519_KEY_LEN);
            if (!crypto_group_proof(hs_resp_proof_label, resp,
                                    HR_PROOF_OFF,
                                    resp + HR_PROOF_OFF) ||
                !crypto_sign(resp, HPV_HS_RESP_SIGNED_LEN,
                             resp + HPV_HS_RESP_SIGNED_LEN) ||
                p2p_conn_write(ssl, resp, sizeof(resp)) != (int)sizeof(resp) ||
                !crypto_derive_session_key(sx_secret, peer_x25519,
                                           my_ed25519_pubkey, peer_pubkey,
                                           false, res->session_key)) {
                memset(sx_secret, 0, sizeof(sx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd); free(res); continue;
            }
            memset(sx_secret, 0, sizeof(sx_secret));

            struct timeval zero = {0, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));

            res->success      = true;
            res->id           = new_id;
            res->hello_type   = hello_type;
            res->fd           = fd;
            res->ssl          = ssl;
            res->have_pubkey  = true;
            res->have_session_key = true;
            snprintf(res->reason, sizeof(res->reason), "%s",
                     job.reason[0] ? job.reason : "inbound-conn");
            memcpy(res->peer_pubkey, peer_pubkey, CRYPTO_PUBKEY_LEN);
            res->do_forw_join = (hello_type == H_JOIN);

        } else {
            
            node_id_t id    = job.target_id;
            uint8_t   hello = job.hello;

#define FAIL_OUTGOING(cleanup_code) do {   \
    cleanup_code;                          \
    pending_out_remove(id);               \
    res->success = false;                 \
    res->id      = id;                    \
    conn_result_t *_fp = res;             \
    if (write(completion_pipe[1], &_fp, sizeof(_fp)) != sizeof(_fp)) \
        free(res);                        \
    goto next_job;                        \
} while(0)

            int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (fd < 0) FAIL_OUTGOING({});

            {
                int flags = fcntl(fd, F_GETFL, 0);
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);

                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                memcpy(&addr.sin_addr.s_addr, id.id,     4);
                memcpy(&addr.sin_port,        id.id + 4, 2);

                int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
                bool direct_ok = false;

                if (rc == 0) {
                    direct_ok = true;
                } else if (errno == EINPROGRESS) {
                    fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
                    struct timeval tv = {5, 0};
                    if (select(fd+1, NULL, &wfds, NULL, &tv) > 0) {
                        int err = 0; socklen_t slen = sizeof(err);
                        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &slen);
                        if (err == 0) direct_ok = true;
                    }
                }

                if (!direct_ok)
                    FAIL_OUTGOING(close(fd));

                fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
            }

            set_socket_opts(fd);

            P2PConn *ssl = p2p_conn_wrap_client(fd);
            if (!ssl)
                FAIL_OUTGOING(close(fd));

            struct timeval rcvto = {5, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));

            uint8_t cx_secret[CRYPTO_X25519_KEY_LEN];
            uint8_t cx_pub[CRYPTO_X25519_KEY_LEN];
            if (!crypto_make_x25519_keypair(cx_secret, cx_pub)) {
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id); free(res); continue;
            }

            uint8_t hs[HPV_HS_LEN];
            if (!crypto_random_bytes(hs, CRYPTO_HS_SALT_LEN)) {
                memset(cx_secret, 0, sizeof(cx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id); free(res); continue;
            }
            hs[HS_HELLO_OFF] = hello;
            uint16_t p_net = htons((uint16_t)my_listen_port);
            memcpy(hs + HS_PORT_OFF,  &p_net,            2);
            memcpy(hs + HS_PUB_OFF, my_ed25519_pubkey,  CRYPTO_PUBKEY_LEN);
            memcpy(hs + HS_X_OFF, cx_pub, CRYPTO_X25519_KEY_LEN);
            if (!solve_handshake_pow(hs)) {
                memset(cx_secret, 0, sizeof(cx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id); free(res); continue;
            }
            if (!crypto_group_proof(hs_req_proof_label, hs,
                                    HS_PROOF_OFF, hs + HS_PROOF_OFF) ||
                !crypto_sign(hs, HPV_HS_SIGNED_LEN,
                             hs + HPV_HS_SIGNED_LEN)) {
                memset(cx_secret, 0, sizeof(cx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id); free(res); continue;
            }

            if (write_all(fd, ssl, hs, HPV_HS_LEN) != HPV_HS_LEN) {
                memset(cx_secret, 0, sizeof(cx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id); free(res); continue;
            }

            uint8_t response;
            if (p2p_conn_read(ssl, &response, 1) != 1) {
                memset(cx_secret, 0, sizeof(cx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id); free(res); continue;
            }

            if (response == H_REJECT) {
                
                uint8_t buf[512];
                int n = p2p_conn_read(ssl, buf, sizeof(buf));
                if (n > 0) {
                    res->reject_count = n / 6;
                    memcpy(res->reject_buf, buf,
                           (size_t)res->reject_count * 6);
                }
                memset(cx_secret, 0, sizeof(cx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id);
                res->success = false;
                conn_result_t *ptr = res;
                if (write(completion_pipe[1], &ptr, sizeof(ptr)) != sizeof(ptr))
                    free(res);
                continue;
            }

            if (response != H_ACCEPT) {
                memset(cx_secret, 0, sizeof(cx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id); free(res); continue;
            }

            bool have_pk = false;
            uint8_t peer_pubkey[CRYPTO_PUBKEY_LEN];
            uint8_t resp[HPV_HS_RESP_LEN];
            resp[0] = response;
            if (!ssl_read_exact(ssl, resp + 1, HPV_HS_RESP_LEN - 1)) {
                memset(cx_secret, 0, sizeof(cx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id); free(res); continue;
            }
            memcpy(peer_pubkey, resp + HR_PUB_OFF, CRYPTO_PUBKEY_LEN);
            const uint8_t *peer_x25519 = resp + HR_X_OFF;
            const uint8_t *peer_sig = resp + HPV_HS_RESP_SIGNED_LEN;
            if (!crypto_verify(resp, HPV_HS_RESP_SIGNED_LEN, peer_sig,
                               peer_pubkey) ||
                !crypto_group_proof_verify(hs_resp_proof_label, resp,
                                           HR_PROOF_OFF,
                                           resp + HR_PROOF_OFF) ||
                !crypto_derive_session_key(cx_secret, peer_x25519,
                                           my_ed25519_pubkey, peer_pubkey,
                                           true, res->session_key)) {
                memset(cx_secret, 0, sizeof(cx_secret));
                p2p_conn_shutdown(ssl); p2p_conn_free(ssl); close(fd);
                pending_out_remove(id); free(res); continue;
            }
            memset(cx_secret, 0, sizeof(cx_secret));
            have_pk = true;

            struct timeval zero = {0, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));

            pending_out_remove(id);

            res->success     = true;
            res->id          = id;
            res->hello_type  = hello;
            res->fd          = fd;
            res->ssl         = ssl;
            res->have_pubkey = have_pk;
            res->have_session_key = true;
            snprintf(res->reason, sizeof(res->reason), "%s",
                     job.reason[0] ? job.reason : "connect");
            if (have_pk) memcpy(res->peer_pubkey, peer_pubkey, CRYPTO_PUBKEY_LEN);
        }

        conn_result_t *ptr = res;
        ssize_t w = write(completion_pipe[1], &ptr, sizeof(ptr));
        if (w != sizeof(ptr)) {
            
            if (res->success) {
                if (res->ssl) { p2p_conn_shutdown(res->ssl); p2p_conn_free(res->ssl); }
                if (res->fd >= 0) close(res->fd);
            }
            free(res);
        }

        next_job: ;   
    }
    return NULL;
}

void conn_pool_init(void)
{
    if (pipe2(completion_pipe, O_CLOEXEC) < 0) {
        exit(1);
    }

    int flags = fcntl(completion_pipe[1], F_GETFL, 0);
    fcntl(completion_pipe[1], F_SETFL, flags | O_NONBLOCK);

    flags = fcntl(completion_pipe[0], F_GETFL, 0);
    fcntl(completion_pipe[0], F_SETFL, flags | O_NONBLOCK);

    pthread_t tid;
    for (int i = 0; i < CONN_WORKERS; i++) {
        if (pthread_create(&tid, NULL, conn_worker_thread, NULL) != 0) {
            exit(1);
        }
        pthread_detach(tid);
    }
}

void conn_pool_shutdown(void)
{
    pthread_mutex_lock(&conn_mutex);
    pool_running = false;
    pthread_cond_broadcast(&conn_cond);
    pthread_mutex_unlock(&conn_mutex);
}

static void conn_post_job(conn_job_t job)
{
    pthread_mutex_lock(&conn_mutex);
    if (conn_queue_count >= CONN_QUEUE_MAX) {
        pthread_mutex_unlock(&conn_mutex);
        net_log("conn_queue full, dropping work");
        if (!job.is_inbound) pending_out_remove(job.target_id);
        if (job.is_inbound)  close(job.inbound_fd);
        return;
    }
    conn_queue[conn_queue_tail] = job;
    conn_queue_tail = (conn_queue_tail + 1) % CONN_QUEUE_MAX;
    conn_queue_count++;
    pthread_cond_signal(&conn_cond);
    pthread_mutex_unlock(&conn_mutex);
}

static void process_completions(void)
{
    conn_result_t *res;
    while (read(completion_pipe[0], &res, sizeof(res)) == sizeof(res)) {
        if (!res) continue;

        if (!res->success) {
            
            if (res->reject_count > 0)
                add_passive(res->reject_buf, res->reject_count);
            free(res);
            continue;
        }

        add_connection(res->fd, res->id, res->ssl,
                       res->have_pubkey ? res->peer_pubkey : NULL,
                       res->have_session_key ? res->session_key : NULL,
                       res->reason);

        if (res->do_forw_join) {
            uint8_t fwd[8];
            fwd[0] = M_FORW_JOIN;
            fwd[1] = 0;
            memcpy(fwd+2, res->id.id, 6);
            for (int j = 0; j < as_count; j++) {
                if (!id_equal(as[j]->id.id, res->id.id))
                    sndpkt(as[j]->id, fwd, 8);
            }
        }
        free(res);
    }
}

static void p2p_shell_prompt(void)
{
    if (isatty(STDIN_FILENO)) {
        printf(C_RED "operator" C_YELLOW "#" C_RED "> " C_RESET);
        fflush(stdout);
    }
}

static void p2p_shell_show_help(void)
{
    printf("commands:\n");
    printf("  /help                    - show this menu\n");
    printf("  /clear                   - clear screen\n");
    printf("  /peers                   - list connected peers as IP:port\n");
    printf("  /net-peers [>5]          - network peers\n");
    printf("  /quit                    - exit program\n");
}

static bool p2p_shell_command_matches(const char *line,
                                      const char *name,
                                      const char **args_out)
{
    if (!line || !name) return false;
    if (*line == '/') line++;

    size_t name_len = strlen(name);
    if (strncmp(line, name, name_len) != 0) return false;
    if (line[name_len] != '\0' && line[name_len] != ' ' && line[name_len] != '\t')
        return false;

    if (args_out) {
        const char *args = line + name_len;
        while (*args == ' ' || *args == '\t') args++;
        *args_out = args;
    }
    return true;
}

static bool p2p_shell_exact_command(const char *line, const char *name)
{
    const char *args = NULL;
    return p2p_shell_command_matches(line, name, &args) && args && *args == '\0';
}

static void p2p_format_duration(long seconds, char out[32])
{
    if (!out) return;
    if (seconds < 0) seconds = 0;
    if (seconds >= 86400)
        snprintf(out, 32, "%ldd%02ldh", seconds / 86400,
                 (seconds % 86400) / 3600);
    else if (seconds >= 3600)
        snprintf(out, 32, "%ldh%02ldm", seconds / 3600,
                 (seconds % 3600) / 60);
    else if (seconds >= 60)
        snprintf(out, 32, "%ldm%02lds", seconds / 60, seconds % 60);
    else
        snprintf(out, 32, "%lds", seconds);
}

static void p2p_shell_show_peers(void)
{
    typedef struct {
        char arch[16];
        int count;
    } arch_count_t;
    
    arch_count_t arch_counts[32];
    int arch_type_count = 0;
    uint32_t seen_ips[1024];
    int seen_count = 0;
    int total_unique = 0;

    printf("Connected Peers (%d total):\n", as_count);
    printf("%-22s %-12s %-20s %-15s\n", "IP:Port", "Architecture", "Connected Since", "Last Activity");
    printf("%-22s %-12s %-20s %-15s\n", "----------------------", "------------", "--------------------", "---------------");

    for (int i = 0; i < as_count; i++) {
        uint32_t ip;
        memcpy(&ip, as[i]->id.id, 4);
        bool seen = false;
        for (int j = 0; j < seen_count; j++) {
            if (seen_ips[j] == ip) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            if (seen_count < 1024) seen_ips[seen_count++] = ip;
            total_unique++;
        }
        
        // The first six bytes of a node ID are its IPv4 address and port.
        struct in_addr peer_addr;
        uint16_t peer_port_net;
        char peer_ip[INET_ADDRSTRLEN] = "?";
        char endpoint[INET_ADDRSTRLEN + 8];
        memcpy(&peer_addr.s_addr, as[i]->id.id, sizeof(peer_addr.s_addr));
        memcpy(&peer_port_net, as[i]->id.id + sizeof(peer_addr.s_addr),
               sizeof(peer_port_net));
        if (!inet_ntop(AF_INET, &peer_addr, peer_ip, sizeof(peer_ip)))
            snprintf(peer_ip, sizeof(peer_ip), "?");
        snprintf(endpoint, sizeof(endpoint), "%s:%u", peer_ip,
                 (unsigned)ntohs(peer_port_net));
        
        // Format connection time
        char conn_time[32] = "Unknown";
        if (as[i]->connected_since > 0) {
            time_t now = time(NULL);
            int seconds_ago = (int)(now - as[i]->connected_since);
            if (seconds_ago < 60) {
                snprintf(conn_time, sizeof(conn_time), "%ds ago", seconds_ago);
            } else if (seconds_ago < 3600) {
                snprintf(conn_time, sizeof(conn_time), "%dm ago", seconds_ago / 60);
            } else {
                snprintf(conn_time, sizeof(conn_time), "%dh ago", seconds_ago / 3600);
            }
        }
        
        // Format last activity time
        char last_activity[32] = "Unknown";
        if (as[i]->last_recv > 0) {
            time_t now = time(NULL);
            int seconds_ago = (int)(now - as[i]->last_recv);
            if (seconds_ago < 60) {
                snprintf(last_activity, sizeof(last_activity), "%ds ago", seconds_ago);
            } else if (seconds_ago < 3600) {
                snprintf(last_activity, sizeof(last_activity), "%dm ago", seconds_ago / 60);
            } else {
                snprintf(last_activity, sizeof(last_activity), "%dh ago", seconds_ago / 3600);
            }
        }
        
        printf("%-22s %-12s %-20s %-15s\n", 
               endpoint,
               as[i]->peer_arch[0] ? as[i]->peer_arch : "unknown",
               conn_time,
               last_activity);
        
        // Count architectures for summary
        bool found = false;
        for (int j = 0; j < arch_type_count; j++) {
            if (strcmp(arch_counts[j].arch, as[i]->peer_arch) == 0) {
                arch_counts[j].count++;
                found = true;
                break;
            }
        }
        if (!found && arch_type_count < 32) {
            snprintf(arch_counts[arch_type_count].arch, 16, "%s", 
                     as[i]->peer_arch[0] ? as[i]->peer_arch : "unknown");
            arch_counts[arch_type_count].count = 1;
            arch_type_count++;
        }
    }

    // Show summary
    printf("\nSummary:\n");
    printf("Total connections: %d\n", as_count);
    printf("Unique IPs: %d\n", total_unique);
    
    if (arch_type_count == 0) {
        printf("Architectures: none\n");
    } else {
        // Sort architectures
        for (int i = 0; i < arch_type_count - 1; i++) {
            for (int j = i + 1; j < arch_type_count; j++) {
                if (strcasecmp(arch_counts[i].arch, arch_counts[j].arch) > 0) {
                    arch_count_t temp = arch_counts[i];
                    arch_counts[i] = arch_counts[j];
                    arch_counts[j] = temp;
                }
            }
        }
        
        printf("Architectures: ");
        for (int i = 0; i < arch_type_count; i++) {
            printf("%s(%d)%s", arch_counts[i].arch, arch_counts[i].count, 
                   i < arch_type_count - 1 ? ", " : "");
        }
        printf("\n");
    }
}


static void p2p_shell_show_operator_banner(int master_sock)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char ip[INET_ADDRSTRLEN] = "0.0.0.0";
    uint16_t port = (uint16_t)my_listen_port;

    memset(&addr, 0, sizeof(addr));
    addr_len = sizeof(addr);
    if (getsockname(master_sock, (struct sockaddr *)&addr, &addr_len) != 0)
        memset(&addr, 0, sizeof(addr));
        
    if (addr.sin_family == AF_INET) {
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        if (addr.sin_port != 0)
            port = ntohs(addr.sin_port);
    }
    printf("listening on %s:%u\n", ip, (unsigned)port);
}

static bool p2p_shell_handle_line(char *line)
{
    while (*line == ' ' || *line == '\t') line++;

    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == ' ' || line[len-1] == '\t'))
        line[--len] = '\0';

    if (len == 0) {
        p2p_shell_prompt();
        return true;
    }
    if (line[0] != '/') {
        printf("invalid command: use /help\n");
        p2p_shell_prompt();
        return true;
    }
    if (p2p_shell_exact_command(line, "help")) {
        p2p_shell_show_help();
        p2p_shell_prompt();
        return true;
    }
    if (p2p_shell_exact_command(line, "clear")) {
        if (isatty(STDIN_FILENO))
            printf("\033[2J\033[H");
        p2p_shell_prompt();
        return true;
    }
    if (p2p_shell_exact_command(line, "peers")) {
        p2p_shell_show_peers();
        p2p_shell_prompt();
        return true;
    }
    const char *netpeers_args = NULL;
    if (p2p_shell_command_matches(line, "net-peers", &netpeers_args)) {
        int window_secs = 0;
        if (netpeers_args && *netpeers_args != '\0') {
            char *end = NULL;
            long v = strtol(netpeers_args, &end, 10);
            while (end && (*end == ' ' || *end == '\t')) end++;
            if (!end || *end != '\0' || v < 5) {
                printf("usage: /net-peers [>5]\n");
                p2p_shell_prompt();
                return true;
            }
            window_secs = (int)v;
        }
        if (!p2p_netpeers_start(window_secs))
            p2p_shell_prompt();
        return true;
    }
    if (p2p_shell_exact_command(line, "guard-status")) {
        p2p_guard_dump_status();
        p2p_shell_prompt();
        return true;
    }
    
    if (p2p_shell_exact_command(line, "quit") || p2p_shell_exact_command(line, "exit")) {
        printf("closing operator\n");
        return false;
    }

    if (p2p_shell_exact_command(line, "mod-status")) {
        overlay_dump_sessions();
        udp_transport_dump_stats();
        p2p_shell_prompt();
        return true;
    }

    if (line[0] == '/') {
        printf("unknown command: %s\n", line);
        p2p_shell_prompt();
        return true;
    }

    printf("invalid command: use /help\n");
    p2p_shell_prompt();
    return true;
}

static bool p2p_shell_read_stdin(bool *disable_shell)
{
    static char line[HPV_PKT_MAX];
    static size_t line_len = 0;
    static bool dropping = false;
    char buf[256];

    *disable_shell = false;

    while (1) {
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
            for (ssize_t i = 0; i < n; i++) {
                char c = buf[i];
                if (c == '\r') continue;
                if (c == '\n') {
                    if (!dropping) {
                        line[line_len] = '\0';
                        if (!p2p_shell_handle_line(line)) return false;
                    } else {
                        printf("line discarded: exceeds %d bytes.\n", HPV_PKT_MAX - 1);
                        p2p_shell_prompt();
                    }
                    line_len = 0;
                    dropping = false;
                    continue;
                }
                if (dropping) continue;
                if (line_len + 1 >= sizeof(line)) {
                    dropping = true;
                    line_len = 0;
                    continue;
                }
                line[line_len++] = c;
            }
            continue;
        }
        if (n == 0) {
            if (p2p_operator_mode)
                return false;
            *disable_shell = true;
            return true;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return true;

        perror("read stdin");
        *disable_shell = true;
        return true;
    }
}

void connect_to(node_id_t id, uint8_t hello)
{
    connect_to_reason(id, hello, "connect");
}

void connect_to_reason(node_id_t id, uint8_t hello, const char *reason)
{
    const char *origin = (reason && reason[0]) ? reason : "connect";
    if (is_self_node(id)) {
        net_log("connect_to %s: self-connection blocked", id2str(id));
        return;
    }
    if (!p2p_node_id_is_public(id)) {
        net_log("connect_to %s: non-public endpoint blocked", id2str(id));
        return;
    }

    if (p2p_guard_under_pressure() && as_count >= n0) {
        net_log("connect_to %s: postponed by guard pressure origin=%s",
                id2str(id), origin);
        add_passive(id.id, 1);
        return;
    }
    
    for (int i = 0; i < as_count; i++)
        if (id_equal(as[i]->id.id, id.id)) return;

    if (!pending_out_add(id)) {
        net_log("connect_to %s: already in flight, ignoring origin=%s",
                id2str(id), origin);
        return;
    }

    net_log("connect_to %s hello=%d origin=%s (async)",
            id2str(id), hello, origin);

    conn_job_t job;
    memset(&job, 0, sizeof(job));
    job.is_inbound = false;
    job.target_id  = id;
    job.hello      = hello;
    snprintf(job.reason, sizeof(job.reason), "%s", origin);
    conn_post_job(job);
}

#define EPOLL_CTX_MASTER ((void *)(uintptr_t)1)
#define EPOLL_CTX_PIPE   ((void *)(uintptr_t)2)
#define EPOLL_CTX_STDIN  ((void *)(uintptr_t)3)

// UDP socket draining removed - UDP transport handles packets internally via udp_transport_tick()

void run_hpv(int master_sock)
{
    my_node_start_time = time(NULL);

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) { exit(1); }

    {
        struct epoll_event ev;
        ev.events   = EPOLLIN;
        ev.data.ptr = EPOLL_CTX_MASTER;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_sock, &ev) < 0)
            { exit(1); }
    }

    {
        struct epoll_event ev;
        ev.events   = EPOLLIN;
        ev.data.ptr = EPOLL_CTX_PIPE;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, completion_pipe[0], &ev) < 0)
            { exit(1); }
    }

    // UDP transport doesn't need epoll - it's called directly via udp_transport_tick()

    bool shell_enabled = false;
    bool shell_poll_stdin = false;
    if (p2p_operator_mode && !watchdog_is_daemon_mode()) {
        int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (flags >= 0)
            fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

        struct epoll_event ev;
        ev.events   = EPOLLIN | EPOLLHUP;
        ev.data.ptr = EPOLL_CTX_STDIN;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) == 0) {
            shell_enabled = true;
            p2p_shell_show_operator_banner(master_sock);
            p2p_shell_prompt();
        } else if (errno != EPERM && errno != EBADF && errno != EINVAL) {
            (void)0;
        } else if (p2p_operator_mode && flags >= 0) {
            shell_enabled = true;
            shell_poll_stdin = true;
            p2p_shell_show_operator_banner(master_sock);
            p2p_shell_prompt();
        }
    }

    struct epoll_event events[MAX_EPOLL_EVENTS];

    time_t last_memory_log = 0;

    bool keep_running = true;
    while (keep_running) {
        watchdog_heartbeat();
        if (shell_enabled && shell_poll_stdin) {
            bool disable_shell = false;
            if (!p2p_shell_read_stdin(&disable_shell))
                break;
            if (disable_shell)
                shell_enabled = false;
        }
        int nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, 1000 );

        time_t now = time(NULL);
        if (p2p_shutdown_signal) {
            p2p_shutdown_signal = 0;
            net_log("shutting down agent");
            break;
        }

        if (p2p_netpeers_tick() && shell_enabled)
            p2p_shell_prompt();

        bool guard_pressure = p2p_guard_under_pressure();

        if (!guard_pressure && now >= last_join_time + join_interval) {
            active_connect();
            last_join_time = now;
        }
        if (!guard_pressure && now >= next_shuffle_time) {
            shuffle();
        }
        if (!guard_pressure || as_count < n0)
            reconnect_tick();
        udp_transport_tick();
        overlay_tick();
        
        /* FIXED: Clean up exec processes periodically */
        extern void cleanup_exec_processes(void);
        cleanup_exec_processes();

        if (now >= last_ping_time + HPV_PING_INTERVAL) {
            
            node_id_t ids[AS_MAX];
            int n = as_count;
            for (int i = 0; i < n; i++) ids[i] = as[i]->id;
            /* extended ping stuff: type(1) + wall_time(8). peer sends back
             * extended pong(25) or whatever */
            {
                uint8_t ping9[9];
                ping9[0] = M_PING;
                uint64_t ping_ts = (uint64_t)time(NULL);
                ping9[1] = (uint8_t)(ping_ts >> 56); ping9[2] = (uint8_t)(ping_ts >> 48);
                ping9[3] = (uint8_t)(ping_ts >> 40); ping9[4] = (uint8_t)(ping_ts >> 32);
                ping9[5] = (uint8_t)(ping_ts >> 24); ping9[6] = (uint8_t)(ping_ts >> 16);
                ping9[7] = (uint8_t)(ping_ts >>  8); ping9[8] = (uint8_t)(ping_ts      );
                for (int i = 0; i < n; i++) sndpkt(ids[i], ping9, sizeof(ping9));
            }
            for (int i = 0; i < n; i++) {
                dht_send(ids[i], M_DHT_PING, my_dht_id.bytes, DHT_ID_BYTES);
                dht_stats.total_pings_sent++;
            }
            last_ping_time = now;
        }

        /* Timeout: ghost session occupies an as[] slot indefinitely and blocks reconnection.
         * TIMEOUT=90s >> HPV_PING_INTERVAL=30s, so a live peer will always
         * have sent at least one PONG before expiration. */
        {
            node_id_t stale[AS_MAX];
            int stale_count = 0;
            for (int i = 0; i < as_count; i++) {
                if (as[i]->last_recv > 0 &&
                    now - as[i]->last_recv > TIMEOUT) {
                    stale[stale_count++] = as[i]->id;
                }
            }
            for (int i = 0; i < stale_count; i++) {
                net_log("peer %s no activity %ds — expelling",
                        id2str(stale[i]), TIMEOUT);
                del_connection_reason(stale[i], 1, "watch-liveness");
            }
        }

        dht_lookups_tick();
        dht_bucket_evictions_tick();
        dht_refresh_buckets();
        if (now >= last_republish_time + DHT_REPUBLISH_INTERVAL)
            dht_republish_keys();

        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < nfds; i++) {
            void *ctx = events[i].data.ptr;

            if (ctx == EPOLL_CTX_MASTER) {
                struct sockaddr_in ca;
                socklen_t clen = sizeof(ca);
                int new_fd = accept4(master_sock,
                                     (struct sockaddr *)&ca, &clen,
                                     SOCK_CLOEXEC);
                if (new_fd > 0) {
                    const char *guard_reason = NULL;
                    if (!p2p_ipv4_is_public(ca.sin_addr.s_addr)) {
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
                        net_log("non-public IP connection from %s rejected",
                                ip);
                        close(new_fd);
                        continue;
                    }
                    if (!p2p_guard_accept_inbound(&ca, &guard_reason)) {
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
                        net_log("connection from %s rejected: %s",
                                ip, guard_reason ? guard_reason : "policy");
                        close(new_fd);
                        continue;
                    }
                    if (!inbound_rate_allow(&ca)) {
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
                        net_log("too many handshakes from %s, connection dropped", ip);
                        close(new_fd);
                        continue;
                    }
                    conn_job_t job;
                    memset(&job, 0, sizeof(job));
                    job.is_inbound    = true;
                    job.inbound_fd    = new_fd;
                    job.inbound_addr  = ca;
                    snprintf(job.reason, sizeof(job.reason), "%s",
                             "inbound-conn");
                    conn_post_job(job);
                }
                continue;
            }

            if (ctx == EPOLL_CTX_PIPE) {
                process_completions();
                continue;
            }

            // EPOLL_CTX_UTP removed - UDP transport uses udp_transport_tick() instead

            if (ctx == EPOLL_CTX_STDIN) {
                bool disable_shell = false;
                if (!p2p_shell_read_stdin(&disable_shell)) {
                    keep_running = false;
                    break;
                }
                if (disable_shell && shell_enabled) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL);
                    shell_enabled = false;
                }
                continue;
            }

            active_node_t *node = (active_node_t *)ctx;
            node_id_t cur_id = node->id; /* FIXED: Declare cur_id in correct scope */
            int node_fd = node->fd; /* FIXED: Store fd for validation */

            bool valid = false;
            for (int j = 0; j < as_count; j++) {
                if (as[j] == node) { valid = true; break; }
            }
            if (!valid) continue;

            if (events[i].events & EPOLLOUT) {
                /* FIXED: Protect wbuf_flush with peer management mutex */
                node_id_t node_id_copy = node->id; /* Copy before taking mutex */
                
                pthread_mutex_lock(&peer_mgmt_mutex);
                
                int r = wbuf_flush(&node->wbuf, node->ssl);
                
                if (r < 0) {
                    pthread_mutex_unlock(&peer_mgmt_mutex);
                    net_log("write error on %s", id2str(node_id_copy)); /* Use copy */
                    del_connection_reason(node_id_copy, 1, "write-error");
                    continue;
                }
                
                if (!wbuf_has_data(&node->wbuf)) {
                    struct epoll_event ev;
                    ev.events   = EPOLLIN;
                    ev.data.ptr = node;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, node->fd, &ev);
                }
                
                pthread_mutex_unlock(&peer_mgmt_mutex);
            }

            if (events[i].events & EPOLLIN) {
                size_t room = sizeof(node->rbuf) - node->rbuf_len;
                if (room == 0) {
                    net_log("read buffer full from %s (%zu bytes); "
                            "probably corrupt frame or peer out of sync",
                            id2str(cur_id), node->rbuf_len);
                    del_connection_reason(cur_id, 1, "read-buffer-full");
                    continue;
                }

                ssize_t n = read_from(node->fd, node->ssl,
                                      node->rbuf + node->rbuf_len,
                                      room);
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                    continue;
                if (n <= 0) {
                    net_log("node %s disconnected, reforming mesh...",
                            id2str(cur_id));
                    del_connection_reason(cur_id, 1, "remote-closed");
                    
                    continue;
                }
                node->rbuf_len += (size_t)n;
                node->last_recv = now;
                process_node_packets(node);
                
                /* FIXED: Revalidate node pointer after process_node_packets() */
                /* process_node_packets() may call del_connection() which frees node */
                node = NULL;
                for (int j = 0; j < as_count; j++) {
                    if (id_equal(as[j]->id.id, cur_id.id) && as[j]->fd == node_fd) {
                        node = as[j];
                        break;
                    }
                }
                if (!node) continue; /* Node was disconnected or replaced, skip EPOLLHUP */
            }

            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                /* Revalidate node again in case it was freed above */
                node = NULL;
                for (int j = 0; j < as_count; j++) {
                    if (id_equal(as[j]->id.id, cur_id.id) && as[j]->fd == node_fd) {
                        node = as[j];
                        break;
                    }
                }
                if (!node) continue; /* Node already disconnected or replaced */
                
                net_log("Node %s: socket error", id2str(node->id));
                del_connection_reason(node->id, 1, "socket-error");
            }
        }
    }

    close(epoll_fd);
    epoll_fd = -1;
}
