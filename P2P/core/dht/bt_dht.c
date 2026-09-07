// bt_dht.c - uses bittorrent dht for bootstrap
//
// implements enough of bep5 to leech peers from public bt network
// ping, find_node, get_peers, announce_peer
// does bencoding manually, no dependencies
//
// runs in single thread, wakes up via pipe on shutdown

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "bt_dht.h"
#include "common.h"

// bt_log just calls net_log
#define bt_log net_log

#define BEN_BUF_MAX  2048
#define BEN_IN_MAX   4096

typedef struct {
    uint8_t  buf[BEN_BUF_MAX];
    size_t   len;
    bool     error;
} ben_enc_t;

static void ben_init(ben_enc_t *b)
{
    b->len   = 0;
    b->error = false;
}

static void ben_raw(ben_enc_t *b, const uint8_t *data, size_t n)
{
    if (b->error) return;
    if (b->len + n > BEN_BUF_MAX) { b->error = true; return; }
    memcpy(b->buf + b->len, data, n);
    b->len += n;
}

static void ben_str(ben_enc_t *b, const char *s, size_t slen)
{
    char hdr[16];
    int  hlen = snprintf(hdr, sizeof(hdr), "%zu:", slen);
    ben_raw(b, (const uint8_t *)hdr, (size_t)hlen);
    ben_raw(b, (const uint8_t *)s, slen);
}

static void ben_cstr(ben_enc_t *b, const char *s)
{
    ben_str(b, s, strlen(s));
}

static void ben_int(ben_enc_t *b, int64_t v)
{
    char buf[32];
    int  n = snprintf(buf, sizeof(buf), "i%llde", (long long)v);
    ben_raw(b, (const uint8_t *)buf, (size_t)n);
}

static void ben_dict_begin(ben_enc_t *b) { ben_raw(b, (const uint8_t *)"d", 1); }
static void ben_dict_end  (ben_enc_t *b) { ben_raw(b, (const uint8_t *)"e", 1); }

// skip over a bencoded thing
static bool ben_skip(const uint8_t *buf, size_t len, size_t *pos)
{
    if (*pos >= len) return false;
    uint8_t c = buf[*pos];

    if (c == 'i') {
        (*pos)++;
        while (*pos < len && buf[*pos] != 'e') (*pos)++;
        if (*pos >= len) return false;
        (*pos)++;
        return true;
    }
    if (c == 'l' || c == 'd') {
        (*pos)++;
        while (*pos < len && buf[*pos] != 'e')
            if (!ben_skip(buf, len, pos)) return false;
        if (*pos >= len) return false;
        (*pos)++;
        return true;
    }
    if (c >= '0' && c <= '9') {
        size_t slen = 0;
        while (*pos < len && buf[*pos] >= '0' && buf[*pos] <= '9') {
            slen = slen * 10 + (buf[*pos] - '0');
            (*pos)++;
        }
        if (*pos >= len || buf[*pos] != ':') return false;
        (*pos)++;
        if (*pos + slen > len) return false;
        *pos += slen;
        return true;
    }
    return false;
}

// read bencoded string
static bool ben_read_str(const uint8_t *buf, size_t len, size_t *pos,
                          const uint8_t **out_ptr, size_t *out_len)
{
    if (*pos >= len || buf[*pos] < '0' || buf[*pos] > '9') return false;
    size_t slen = 0;
    while (*pos < len && buf[*pos] >= '0' && buf[*pos] <= '9') {
        slen = slen * 10 + (buf[*pos] - '0');
        (*pos)++;
    }
    if (*pos >= len || buf[*pos] != ':') return false;
    (*pos)++;
    if (*pos + slen > len) return false;
    *out_ptr = buf + *pos;
    *out_len = slen;
    *pos    += slen;
    return true;
}

// look for key in dict, return pos or SIZE_MAX
static size_t ben_dict_find(const uint8_t *buf, size_t len,
                             size_t start, const char *key)
{
    if (start >= len || buf[start] != 'd') return SIZE_MAX;
    size_t pos = start + 1;
    size_t klen = strlen(key);

    while (pos < len && buf[pos] != 'e') {
        const uint8_t *kptr;
        size_t         kl;
        if (!ben_read_str(buf, len, &pos, &kptr, &kl)) break;

        if (kl == klen && memcmp(kptr, key, klen) == 0)
            return pos;

        // skip over value
        if (!ben_skip(buf, len, &pos)) break;
    }
    return SIZE_MAX;
}



#define BT_NODE_ID_LEN   20
#define BT_COMPACT_NODE  26  // 20 node_id + 4 IP + 2 port
#define BT_COMPACT_PEER   6  // 4 IP + 2 port

typedef struct {
    uint8_t          id[BT_NODE_ID_LEN];
    struct sockaddr_in addr;
    time_t           last_seen;
    bool             good;
} bt_node_t;



static pthread_t   bt_thread;
static bool        bt_thread_started = false;
static int         bt_stop_pipe[2]   = {-1, -1};

static int         bt_udp_fd         = -1;
static int         bt_local_port     = 0;
static uint8_t     bt_infohash[BT_NODE_ID_LEN];
static uint8_t     bt_node_id[BT_NODE_ID_LEN];


static uint8_t     bt_group_key[32];            // copy of group key
static bool        bt_group_key_set = false;
static int         bt_last_day      = -1;       // day of year of last derivation

static bt_node_t   bt_rt[BT_ROUTING_MAX];   // mini bt routing table
static int         bt_rt_count = 0;
static pthread_mutex_t bt_rt_mutex = PTHREAD_MUTEX_INITIALIZER;

static int         bt_peers_found_total = 0;
static uint16_t    bt_tid_counter = 0;



typedef struct { const char *ip; int port; } bt_bootstrap_entry_t;

static const bt_bootstrap_entry_t bt_bootstrap_nodes[BT_BOOTSTRAP_COUNT] = {
#define BT_BOOTSTRAP_NODE(ip, port) { (ip), (port) },
    P2P_BT_DHT_BOOTSTRAP_NODES(BT_BOOTSTRAP_NODE)
#undef BT_BOOTSTRAP_NODE
};


static void bt_generate_node_id(void)
{
    crypto_random_bytes(bt_node_id, BT_NODE_ID_LEN);
    for (int i = 0; i < 4; i++)
        bt_node_id[i] ^= bt_infohash[i];
}


static void bt_derive_daily_infohash(void)
{
    time_t now = time(NULL);
    struct tm utc;
    gmtime_r(&now, &utc);

    if (utc.tm_yday == bt_last_day && bt_last_day >= 0)
        return;

    char suffix[24];
    int slen = snprintf(suffix, sizeof(suffix), "p2p-bt-v2-%04d-%02d-%02d",
                        1900 + utc.tm_year, utc.tm_mon + 1, utc.tm_mday);
    slen += 1;

    uint8_t material[32 + 24];
    if (bt_group_key_set)
        memcpy(material, bt_group_key, 32);
    else
        memset(material, 0, 32);
    memcpy(material + 32, suffix, (size_t)slen);

    uint8_t digest[32];
    sha256(material, 32 + (size_t)slen, digest);
    memcpy(bt_infohash, digest, BT_NODE_ID_LEN);

    bt_last_day = utc.tm_yday;

    bt_log("infohash rotated for %04d-%02d-%02d → %02x%02x%02x%02x...",
           1900 + utc.tm_year, utc.tm_mon + 1, utc.tm_mday,
           bt_infohash[0], bt_infohash[1], bt_infohash[2], bt_infohash[3]);
}

static void bt_rt_add(const uint8_t id[BT_NODE_ID_LEN],
                       const struct sockaddr_in *addr)
{
    pthread_mutex_lock(&bt_rt_mutex);

    for (int i = 0; i < bt_rt_count; i++) {
        if (memcmp(bt_rt[i].id, id, BT_NODE_ID_LEN) == 0) {
            bt_rt[i].addr      = *addr;
            bt_rt[i].last_seen = time(NULL);
            bt_rt[i].good      = true;
            pthread_mutex_unlock(&bt_rt_mutex);
            return;
        }
    }

    if (bt_rt_count < BT_ROUTING_MAX) {
        memcpy(bt_rt[bt_rt_count].id, id, BT_NODE_ID_LEN);
        bt_rt[bt_rt_count].addr      = *addr;
        bt_rt[bt_rt_count].last_seen = time(NULL);
        bt_rt[bt_rt_count].good      = true;
        bt_rt_count++;
    } else {
        int oldest = 0;
        for (int i = 1; i < bt_rt_count; i++)
            if (bt_rt[i].last_seen < bt_rt[oldest].last_seen)
                oldest = i;
        memcpy(bt_rt[oldest].id, id, BT_NODE_ID_LEN);
        bt_rt[oldest].addr      = *addr;
        bt_rt[oldest].last_seen = time(NULL);
        bt_rt[oldest].good      = true;
    }

    pthread_mutex_unlock(&bt_rt_mutex);
}



static uint16_t bt_next_tid(void)
{
    return bt_tid_counter++;
}


static size_t bt_make_find_node(uint8_t *out, size_t out_max,
                                 const uint8_t target[BT_NODE_ID_LEN],
                                 uint16_t *tid_out)
{
    ben_enc_t b;
    ben_init(&b);
    uint16_t tid = bt_next_tid();
    if (tid_out) *tid_out = tid;
    uint8_t tid_bytes[2] = { (uint8_t)(tid >> 8), (uint8_t)(tid & 0xff) };

    ben_dict_begin(&b);
      ben_cstr(&b, "a");
      ben_dict_begin(&b);
        ben_cstr(&b, "id");
        ben_str(&b, (const char *)bt_node_id, BT_NODE_ID_LEN);
        ben_cstr(&b, "target");
        ben_str(&b, (const char *)target, BT_NODE_ID_LEN);
      ben_dict_end(&b);
      ben_cstr(&b, "q"); ben_cstr(&b, "find_node");
      ben_cstr(&b, "t"); ben_str(&b, (const char *)tid_bytes, 2);
      ben_cstr(&b, "y"); ben_cstr(&b, "q");
    ben_dict_end(&b);

    if (b.error || b.len > out_max) return 0;
    memcpy(out, b.buf, b.len);
    return b.len;
}


static size_t bt_make_get_peers(uint8_t *out, size_t out_max, uint16_t *tid_out)
{
    ben_enc_t b;
    ben_init(&b);
    uint16_t tid = bt_next_tid();
    if (tid_out) *tid_out = tid;
    uint8_t tid_bytes[2] = { (uint8_t)(tid >> 8), (uint8_t)(tid & 0xff) };

    ben_dict_begin(&b);
      ben_cstr(&b, "a");
      ben_dict_begin(&b);
        ben_cstr(&b, "id");
        ben_str(&b, (const char *)bt_node_id, BT_NODE_ID_LEN);
        ben_cstr(&b, "info_hash");
        ben_str(&b, (const char *)bt_infohash, BT_NODE_ID_LEN);
      ben_dict_end(&b);
      ben_cstr(&b, "q"); ben_cstr(&b, "get_peers");
      ben_cstr(&b, "t"); ben_str(&b, (const char *)tid_bytes, 2);
      ben_cstr(&b, "y"); ben_cstr(&b, "q");
    ben_dict_end(&b);

    if (b.error || b.len > out_max) return 0;
    memcpy(out, b.buf, b.len);
    return b.len;
}


static size_t bt_make_announce(uint8_t *out, size_t out_max,
                                const uint8_t *token, size_t token_len,
                                uint16_t *tid_out)
{
    ben_enc_t b;
    ben_init(&b);
    uint16_t tid = bt_next_tid();
    if (tid_out) *tid_out = tid;
    uint8_t tid_bytes[2] = { (uint8_t)(tid >> 8), (uint8_t)(tid & 0xff) };

    ben_dict_begin(&b);
      ben_cstr(&b, "a");
      ben_dict_begin(&b);
        ben_cstr(&b, "id");
        ben_str(&b, (const char *)bt_node_id, BT_NODE_ID_LEN);
        ben_cstr(&b, "implied_port"); ben_int(&b, 0);
        ben_cstr(&b, "info_hash");
        ben_str(&b, (const char *)bt_infohash, BT_NODE_ID_LEN);
        ben_cstr(&b, "port"); ben_int(&b, bt_local_port);
        ben_cstr(&b, "token");
        ben_str(&b, (const char *)token, token_len);
      ben_dict_end(&b);
      ben_cstr(&b, "q"); ben_cstr(&b, "announce_peer");
      ben_cstr(&b, "t"); ben_str(&b, (const char *)tid_bytes, 2);
      ben_cstr(&b, "y"); ben_cstr(&b, "q");
    ben_dict_end(&b);

    if (b.error || b.len > out_max) return 0;
    memcpy(out, b.buf, b.len);
    return b.len;
}



static void bt_send(const struct sockaddr_in *dest,
                    const uint8_t *msg, size_t len)
{
    if (bt_udp_fd < 0 || !msg || len == 0) return;
    sendto(bt_udp_fd, msg, len, 0,
           (const struct sockaddr *)dest, sizeof(*dest));
}


static void bt_parse_compact_nodes(const uint8_t *data, size_t len)
{
    size_t off = 0;
    int added = 0;
    while (off + BT_COMPACT_NODE <= len) {
        uint8_t id[BT_NODE_ID_LEN];
        memcpy(id, data + off, BT_NODE_ID_LEN);
        off += BT_NODE_ID_LEN;

        uint32_t ip_net;
        uint16_t port_net;
        memcpy(&ip_net,   data + off,     4);
        memcpy(&port_net, data + off + 4, 2);
        off += 6;

        if (port_net == 0) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = ip_net;
        addr.sin_port        = port_net;

        bt_rt_add(id, &addr);
        added++;
    }
}


static void bt_parse_peers(const uint8_t *buf, size_t buf_len, size_t vpos)
{
    if (vpos >= buf_len || buf[vpos] != 'l') return;
    size_t pos = vpos + 1;
    int count  = 0;

    while (pos < buf_len && buf[pos] != 'e' && count < BT_MAX_PEERS) {
        const uint8_t *peer_data;
        size_t         peer_len;
        if (!ben_read_str(buf, buf_len, &pos, &peer_data, &peer_len)) break;
        if (peer_len != BT_COMPACT_PEER) continue;

        uint32_t ip_net;
        uint16_t port_net;
        memcpy(&ip_net,   peer_data,     4);
        memcpy(&port_net, peer_data + 4, 2);
        int port = ntohs(port_net);

        if (port == 0) continue;

        char ip_str[INET_ADDRSTRLEN];
        struct in_addr ia;
        ia.s_addr = ip_net;
        inet_ntop(AF_INET, &ia, ip_str, sizeof(ip_str));

        node_id_t nid;
        if (node_id_from_ip_port(ip_str, port, &nid)) {
            if (is_self_node(nid)) {
                bt_log("discarded own peer %s:%d", ip_str, port);
                continue;
            }
            
            bt_log("peer via BT-DHT: %s:%d", ip_str, port);
            add_passive(nid.id, 1);
            dht_bootstrap(nid);
            bt_peers_found_total++;
            count++;
        }
    }

    if (count > 0)
        bt_log("delivered %d peers to P2P system", count);
}


#define BT_TOKEN_MAX_LEN  20
#define BT_TOKEN_TABLE    32

typedef struct {
    struct sockaddr_in addr;
    uint8_t  token[BT_TOKEN_MAX_LEN];
    size_t   token_len;
    time_t   received_at;
} bt_token_t;

static bt_token_t bt_token_table[BT_TOKEN_TABLE];
static int        bt_token_count = 0;

static void bt_token_store(const struct sockaddr_in *addr,
                            const uint8_t *tok, size_t tlen)
{
    if (tlen == 0 || tlen > BT_TOKEN_MAX_LEN) return;

    // look for existing for this addr
    for (int i = 0; i < bt_token_count; i++) {
        if (bt_token_table[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            bt_token_table[i].addr.sin_port        == addr->sin_port) {
            memcpy(bt_token_table[i].token, tok, tlen);
            bt_token_table[i].token_len   = tlen;
            bt_token_table[i].received_at = time(NULL);
            return;
        }
    }

    int slot = bt_token_count < BT_TOKEN_TABLE
               ? bt_token_count++
               : (bt_token_count % BT_TOKEN_TABLE);

    bt_token_table[slot].addr        = *addr;
    memcpy(bt_token_table[slot].token, tok, tlen);
    bt_token_table[slot].token_len   = tlen;
    bt_token_table[slot].received_at = time(NULL);
}

static bool bt_token_get(const struct sockaddr_in *addr,
                          uint8_t *tok_out, size_t *tlen_out)
{
    for (int i = 0; i < bt_token_count; i++) {
        if (bt_token_table[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            bt_token_table[i].addr.sin_port        == addr->sin_port &&
            bt_token_table[i].token_len > 0) {
            memcpy(tok_out, bt_token_table[i].token,
                   bt_token_table[i].token_len);
            *tlen_out = bt_token_table[i].token_len;
            return true;
        }
    }
    return false;
}

// parse incoming dht message
static void bt_handle_packet(const uint8_t *buf, size_t len,
                              const struct sockaddr_in *from)
{
    if (buf[0] != 'd') return;

    size_t ypos = ben_dict_find(buf, len, 0, "y");
    if (ypos == SIZE_MAX) return;
    const uint8_t *yval;
    size_t         ylen;
    size_t         ypos2 = ypos;
    if (!ben_read_str(buf, len, &ypos2, &yval, &ylen)) return;
    if (ylen != 1) return;

    if (yval[0] == 'e') {
        return;
    }
    if (yval[0] != 'r') {
        return;
    }

    size_t rpos = ben_dict_find(buf, len, 0, "r");
    if (rpos == SIZE_MAX) return;
    if (rpos >= len || buf[rpos] != 'd') return;

    size_t id_pos = ben_dict_find(buf, len, rpos, "id");
    if (id_pos != SIZE_MAX) {
        const uint8_t *id_val;
        size_t         id_len;
        size_t         id_pos2 = id_pos;
        if (ben_read_str(buf, len, &id_pos2, &id_val, &id_len) &&
            id_len == BT_NODE_ID_LEN) {
            bt_rt_add(id_val, from);
        }
    }


    size_t nodes_pos = ben_dict_find(buf, len, rpos, "nodes");
    if (nodes_pos != SIZE_MAX) {
        const uint8_t *nodes_val;
        size_t         nodes_len;
        size_t         nodes_pos2 = nodes_pos;
        if (ben_read_str(buf, len, &nodes_pos2, &nodes_val, &nodes_len))
            bt_parse_compact_nodes(nodes_val, nodes_len);
    }


    size_t values_pos = ben_dict_find(buf, len, rpos, "values");
    if (values_pos != SIZE_MAX)
        bt_parse_peers(buf, len, values_pos);


    size_t tok_pos = ben_dict_find(buf, len, rpos, "token");
    if (tok_pos != SIZE_MAX) {
        const uint8_t *tok_val;
        size_t         tok_len;
        size_t         tok_pos2 = tok_pos;
        if (ben_read_str(buf, len, &tok_pos2, &tok_val, &tok_len))
            bt_token_store(from, tok_val, tok_len);
    }
}

// add bt bootstrap nodes to routing table
static void bt_resolve_bootstraps(void)
{
    for (int i = 0; i < BT_BOOTSTRAP_COUNT; i++) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons((uint16_t)bt_bootstrap_nodes[i].port);

        if (inet_aton(bt_bootstrap_nodes[i].ip, &addr.sin_addr) == 0) {
            bt_log("invalid IP in bootstrap[%d]: %s", i, bt_bootstrap_nodes[i].ip);
            continue;
        }

    // temp node id: ip in first 4 bytes, rest zeros
        uint8_t fake_id[BT_NODE_ID_LEN];
        memset(fake_id, 0, sizeof(fake_id));
        memcpy(fake_id, &addr.sin_addr.s_addr, 4);

        bt_rt_add(fake_id, &addr);
        bt_log("bootstrap: %s:%d added",
               bt_bootstrap_nodes[i].ip, bt_bootstrap_nodes[i].port);
    }
}

// send find_node, get_peers, announce to known nodes
static void bt_do_round(void)
{
    uint8_t msg[BEN_BUF_MAX];
    size_t  mlen;

    // rotate infohash if day changed (hajime style)
    bt_derive_daily_infohash();

    pthread_mutex_lock(&bt_rt_mutex);
    int n = bt_rt_count;
    bt_node_t snapshot[BT_ROUTING_MAX];
    memcpy(snapshot, bt_rt, sizeof(bt_node_t) * (size_t)n);
    pthread_mutex_unlock(&bt_rt_mutex);

    if (n == 0) {
        bt_log("routing table empty, resolving bootstraps...");
        bt_resolve_bootstraps();
        return;
    }

    bt_log("bootstrap round: %d nodes in RT", n);

    int get_peers_count  = 0;
    int announce_count   = 0;

    for (int i = 0; i < n; i++) {
        bt_node_t *node = &snapshot[i];

        mlen = bt_make_find_node(msg, sizeof(msg), bt_infohash, NULL);
        if (mlen > 0)
            bt_send(&node->addr, msg, mlen);

        mlen = bt_make_get_peers(msg, sizeof(msg), NULL);
        if (mlen > 0) {
            bt_send(&node->addr, msg, mlen);
            get_peers_count++;
        }

        uint8_t tok[BT_TOKEN_MAX_LEN];
        size_t  tok_len = 0;
        if (bt_token_get(&node->addr, tok, &tok_len)) {
            mlen = bt_make_announce(msg, sizeof(msg), tok, tok_len, NULL);
            if (mlen > 0) {
                bt_send(&node->addr, msg, mlen);
                announce_count++;
            }
        }
    }

    bt_log("round: get_peers=%d announces=%d peers_total=%d",
           get_peers_count, announce_count, bt_peers_found_total);
}

// bt dht thread main loop
static void *bt_thread_func(void *arg)
{
    (void)arg;
    bt_log("BT-DHT thread started (infohash=%02x%02x%02x%02x...)",
           bt_infohash[0], bt_infohash[1], bt_infohash[2], bt_infohash[3]);

    // create udp socket
    bt_udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (bt_udp_fd < 0) {
        bt_log("ERROR: could not create UDP socket: %s", strerror(errno));
        return NULL;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port        = htons((uint16_t)bt_local_port);

    if (bind(bt_udp_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        bt_log("UDP bind on port %d failed (%s), using ephemeral port",
               bt_local_port, strerror(errno));
        bind_addr.sin_port = 0;
        if (bind(bt_udp_fd, (struct sockaddr *)&bind_addr,
                 sizeof(bind_addr)) < 0) {
            bt_log("ERROR: UDP bind failed definitively: %s", strerror(errno));
            close(bt_udp_fd);
            bt_udp_fd = -1;
            return NULL;
        }
    }

    {
        struct sockaddr_in actual;
        socklen_t actual_len = sizeof(actual);
        int udp_port = bt_local_port;
        if (getsockname(bt_udp_fd, (struct sockaddr *)&actual,
                        &actual_len) == 0)
            udp_port = ntohs(actual.sin_port);
        bt_log("UDP socket ready on port %d; announce TCP=%d",
               udp_port, bt_local_port);
    }

    bt_resolve_bootstraps();
    bt_do_round();

    time_t last_round = time(NULL);

    uint8_t recv_buf[BEN_IN_MAX];

    while (1) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(bt_udp_fd, &rset);
        FD_SET(bt_stop_pipe[0], &rset);
        int maxfd = bt_udp_fd > bt_stop_pipe[0]
                    ? bt_udp_fd : bt_stop_pipe[0];

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int sel = select(maxfd + 1, &rset, NULL, NULL, &tv);

        if (sel < 0) {
            if (errno == EINTR) continue;
            bt_log("select error: %s", strerror(errno));
            break;
        }

        if (FD_ISSET(bt_stop_pipe[0], &rset)) {
            bt_log("stop signal received");
            break;
        }

        if (sel > 0 && FD_ISSET(bt_udp_fd, &rset)) {
            struct sockaddr_in from;
            socklen_t          from_len = sizeof(from);

            ssize_t n = recvfrom(bt_udp_fd, recv_buf, sizeof(recv_buf), 0,
                                 (struct sockaddr *)&from, &from_len);
            if (n > 0)
                bt_handle_packet(recv_buf, (size_t)n, &from);
        }

        time_t now = time(NULL);
        if (now - last_round >= BT_REFRESH_INTERVAL) {
            bt_do_round();
            last_round = now;
        }
    }

    close(bt_udp_fd);
    bt_udp_fd = -1;
    bt_log("BT-DHT thread terminated. peers_discovered=%d", bt_peers_found_total);
    return NULL;
}

/* public api */

void bt_dht_init(int local_port, const uint8_t *group_key_32)
{
    bt_local_port = (local_port > 0) ? local_port : P2P_DEFAULT_PORT;

    if (group_key_32) {
        memcpy(bt_group_key, group_key_32, 32);
        bt_group_key_set = true;
    } else {
        memset(bt_group_key, 0, 32);
        bt_group_key_set = false;
    }
    bt_last_day = -1;

    bt_derive_daily_infohash();

    bt_generate_node_id();

    memset(bt_rt,          0, sizeof(bt_rt));
    memset(bt_token_table, 0, sizeof(bt_token_table));
    bt_rt_count          = 0;
    bt_token_count       = 0;
    bt_peers_found_total = 0;
    bt_tid_counter       = 0;

    bt_log("initialized: port=%d infohash=%02x%02x%02x%02x...",
           bt_local_port,
           bt_infohash[0], bt_infohash[1], bt_infohash[2], bt_infohash[3]);
}

void bt_dht_start(void)
{
    if (bt_thread_started) return;

    if (pipe(bt_stop_pipe) < 0) {
        bt_log("ERROR: could not create signal pipe: %s",
               strerror(errno));
        return;
    }

    fcntl(bt_stop_pipe[0], F_SETFL,
          fcntl(bt_stop_pipe[0], F_GETFL) | O_NONBLOCK);

    if (pthread_create(&bt_thread, NULL, bt_thread_func, NULL) != 0) {
        bt_log("ERROR: could not create BT-DHT thread: %s", strerror(errno));
        close(bt_stop_pipe[0]);
        close(bt_stop_pipe[1]);
        bt_stop_pipe[0] = bt_stop_pipe[1] = -1;
        return;
    }

    bt_thread_started = true;
    bt_log("thread launched");
}

void bt_dht_stop(void)
{
    if (!bt_thread_started) return;

    if (bt_stop_pipe[1] >= 0) {
        uint8_t sig = 1;
        { ssize_t _wr = write(bt_stop_pipe[1], &sig, 1); (void)_wr; }
    }

    pthread_join(bt_thread, NULL);
    bt_thread_started = false;

    if (bt_stop_pipe[0] >= 0) { close(bt_stop_pipe[0]); bt_stop_pipe[0] = -1; }
    if (bt_stop_pipe[1] >= 0) { close(bt_stop_pipe[1]); bt_stop_pipe[1] = -1; }

    bt_log("stopped");
}
