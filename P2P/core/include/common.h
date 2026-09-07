#ifndef P2P_COMMON_H
#define P2P_COMMON_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <termios.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#include <pthread.h>

#include "monocypher.h"
#include "bootstrap_config.h"
#include "bt_dht.h"

#define H_JOIN         72
#define H_NEIGHBOR_LO  73
#define H_NEIGHBOR_HI  74
#define H_ACCEPT       75
#define H_REJECT       76

#define P2P_DEFAULT_PORT   3722  // fixed iot port
#define P2P_GOSSIP_FANOUT  3
#define P2P_DEFAULT_GOSSIP_TTL 15
#define P2P_BROADCAST_TTL_MAX 10
#define P2P_BROADCAST_FANOUT_MAX 3

#define RECONNECT_BACKOFF_BASE      5
#define RECONNECT_BACKOFF_MAX_SEC   120  
#define RECONNECT_TABLE_MAX         128   // Reconnect backoff (was 512 = 13 KB waste)
#define RECONNECT_TICK_INTERVAL     5
#define RECONNECT_MAX_ATTEMPTS      8
#define RECONNECT_CONNECT_TIMEOUT   3
#define HPV_PING_INTERVAL           30


#define M_JOIN         H_JOIN
#define M_DISCONNECT   1
#define M_FORW_JOIN    2
#define M_SHUFFLE      3
#define M_WHISPER      4
#define M_BROADCAST    5
#define M_PING         6
#define M_PONG         7   // ping response: legacy start_time(8) or echo+now+start(24)
#define M_ARCH         8   // arch info: 1 byte type + ascii string (max 15 chars + null)

#define M_DHT_PING        10
#define M_DHT_PONG        11
#define M_DHT_FIND_NODE   12
#define M_DHT_FOUND_NODE  13
#define M_DHT_FIND_VALUE  14
#define M_DHT_FOUND_VALUE 15
#define M_DHT_STORE       16
#define M_DHT_STORE_ACK   17

#define TIMEOUT        90
#define HPV_PKT_MAX    1024

#define CRYPTO_MAC_LEN    16
#define CRYPTO_SIG_LEN    64
#define CRYPTO_PUBKEY_LEN 32
#define CRYPTO_SECKEY_LEN 64
#define CRYPTO_SEED_LEN   32
#define CRYPTO_X25519_KEY_LEN 32
#define CRYPTO_HS_SALT_LEN 8
#define CRYPTO_POW_NONCE_LEN 8
#define CRYPTO_HS_PROOF_LEN 16
#define P2P_HANDSHAKE_POW_BITS 16
#define CRYPTO_NONCE_LEN  24
#define CRYPTO_NONCE_PREFIX_LEN 16
#define CRYPTO_SEAL_OVERHEAD (CRYPTO_NONCE_LEN + CRYPTO_MAC_LEN)
#define HPV_PKT_WIRE_MAX  (HPV_PKT_MAX + CRYPTO_SEAL_OVERHEAD)
#define HPV_HS_SIGNED_LEN (CRYPTO_HS_SALT_LEN + 1 + 2 + CRYPTO_PUBKEY_LEN + CRYPTO_X25519_KEY_LEN + CRYPTO_POW_NONCE_LEN + CRYPTO_HS_PROOF_LEN)
#define HPV_HS_LEN        (HPV_HS_SIGNED_LEN + CRYPTO_SIG_LEN)
#define HPV_HS_RESP_SIGNED_LEN (1 + CRYPTO_HS_SALT_LEN + CRYPTO_PUBKEY_LEN + CRYPTO_X25519_KEY_LEN + CRYPTO_HS_PROOF_LEN)
#define HPV_HS_RESP_LEN        (HPV_HS_RESP_SIGNED_LEN + CRYPTO_SIG_LEN)

#define DHT_ID_BITS    160
#define DHT_ID_BYTES   20
#define DHT_K          4
#define DHT_ALPHA      2
#define DHT_BUCKETS    DHT_ID_BITS
#define DHT_STORE_MAX  128    
#define DHT_TTL        3600
#define DHT_VALUE_MAX  192

#define DHT_SHORTLIST_MAX           (DHT_K * 3)
#define DHT_QUERY_TIMEOUT           10
#define DHT_LOOKUP_TIMEOUT          60
#define DHT_LOOKUP_MAX              16
#define DHT_STORE_RATE_MAX          6
#define DHT_BUCKET_REFRESH_INTERVAL 600
#define DHT_REPUBLISH_INTERVAL      3300
#define DHT_FAILURE_THRESHOLD       3


#define MAX_EPOLL_EVENTS  128

#define CONN_WORKERS    1
#define CONN_QUEUE_MAX  64   // Worker queue (was 256 = 15 KB waste)

#define WBUF_SIZE  (HPV_PKT_WIRE_MAX + 16u)  // framing(3)+wire_max(1064)+margin

#define PKT_POOL_SIZE  8
#define PKT_BUF_SIZE   (HPV_PKT_WIRE_MAX + 8)

#define P2P_BC_SUBTYPE  0xBB

#define P2PCONN_ERROR_WANT_WRITE 2
#define P2PCONN_ERROR_WANT_READ  3

typedef struct { uint8_t id[6]; }           node_id_t;
typedef struct { uint8_t bytes[DHT_ID_BYTES]; } dht_id_t;

typedef struct {
    int fd;
} P2PConn; 

typedef struct {
    dht_id_t  dht_id;
    node_id_t net_id;
} dht_node_t;

typedef struct {
    int    failures;
    int    successes;
    time_t last_seen;
    time_t last_failure;
} dht_node_stats_t;

typedef struct {
    dht_node_t       entries[DHT_K];
    dht_node_stats_t stats[DHT_K];
    int              count;
    time_t           last_changed;
    dht_node_t       pending;
    bool             has_pending;
    time_t           ping_sent_at;
    int              ping_slot;
} kbucket_t;

typedef struct {
    dht_id_t key;
    uint8_t  value[DHT_VALUE_MAX];
    size_t   value_len;
    time_t   expire;
    time_t   stored_at;
    bool     used;
} dht_store_entry_t;

typedef struct {
    uint8_t  data[WBUF_SIZE];
    uint32_t rpos;  
    uint32_t wpos;  
} write_buf_t;

#define CLOCK_SAMPLES_MAX 8
#define CLOCK_SAMPLE_MAX_AGE_SECS 180

typedef struct {
    int       fd;
    P2PConn *ssl;
    node_id_t id;      /* transport endpoint: IPv4 + port */
    dht_id_t  dht_id;  /* ephemeral session identity: SHA256(pubkey)[0:20] */
    uint8_t   peer_ed25519_pubkey[CRYPTO_PUBKEY_LEN];
    bool      pubkey_valid;
    bool      trust_verified;
    uint8_t   session_key[32];
    bool      session_key_valid;
    uint8_t   rbuf[HPV_PKT_WIRE_MAX + 16]; // framing(3)+wire_max(1064)+margin
    size_t    rbuf_len;
    write_buf_t wbuf;        
    uint64_t  tx_nonce;
    time_t    connected_since; // timestamp when connection was established
    time_t    peer_start_time;
    time_t    last_recv;
    char      peer_arch[16];
    int64_t   clock_samples[CLOCK_SAMPLES_MAX];
    time_t    clock_sample_seen[CLOCK_SAMPLES_MAX];
    int       clock_sample_count;
    int       clock_sample_head;
    bool      clock_offset_valid;
} active_node_t;

typedef struct { node_id_t id; } passive_node_t;

typedef struct { uint32_t expire; uint64_t hash; } backlog_entry_t;

typedef struct {
    node_id_t peer;
    int       store_count;
    time_t    window_start;
} peer_rate_t;

typedef struct {
    bool     used;
    uint32_t ip_addr;
    int      handshake_count;
    time_t   window_start;
} inbound_rate_t;

typedef struct {
    bool       active;
    bool       is_find_value;
    dht_id_t   target;
    dht_node_t shortlist[DHT_SHORTLIST_MAX];
    uint8_t    dist[DHT_SHORTLIST_MAX][DHT_ID_BYTES];
    int        shortlist_count;
    bool       queried[DHT_SHORTLIST_MAX];
    bool       responded[DHT_SHORTLIST_MAX];
    bool       failed[DHT_SHORTLIST_MAX];
    time_t     query_time[DHT_SHORTLIST_MAX];
    int        active_queries;
    bool       finished;
    time_t     start_time;
    uint8_t    found_value[DHT_VALUE_MAX];
    size_t     found_value_len;
    bool       value_found;
    uint32_t   lookup_id;
} dht_lookup_t;

typedef struct {
    node_id_t id;
    int       attempts;
    time_t    retry_after;
    bool      in_use;
} reconnect_entry_t;

typedef struct {
    int      peers_active;
    int      buckets_used;
    int      store_entries;
    int      lookups_active;
    double   lookup_latency_avg_ms;
    uint64_t total_lookups;
    uint64_t successful_lookups;
    uint64_t total_stores;
    uint64_t total_pings_sent;
    uint64_t total_pings_recv;
} dht_stats_t;

typedef struct {
    bool      used;
    bool      is_inbound;
    node_id_t target_id;
    uint8_t   hello;
    int       inbound_fd;
    struct sockaddr_in inbound_addr;
    char      reason[32];
} conn_job_t;

#define AS_MAX  64
#define PS_MAX  1024
#define BL_MAX  2048   // 2k entries: handles ~17 msg/sec (was 10240 = 360 KB waste)


#define RATE_TABLE_MAX 64
#define INBOUND_RATE_MAX 128
#define INBOUND_HANDSHAKE_RATE_MAX 12
#define INBOUND_HANDSHAKE_WINDOW 60

typedef struct {
    bool      success;
    node_id_t id;
    uint8_t   hello_type;
    int       fd;
    P2PConn *ssl;
    uint8_t   peer_pubkey[CRYPTO_PUBKEY_LEN];
    bool      have_pubkey;
    uint8_t   session_key[32];
    bool      have_session_key;
    bool      do_forw_join;
    uint8_t   reject_buf[512];
    int       reject_count;
    char      reason[32];
} conn_result_t;


extern int join_interval;
extern int arwl;
extern int prwl;
extern int mrwl;
extern int n0;
extern int na;
extern int nb;
extern int np;
extern int ka;
extern int kp;
extern int shuffle0;
extern int shuffle1;
extern int my_listen_port;
extern char my_arch[16];
extern int gossip_ttl;
extern int overlay_max_sessions;


extern active_node_t  *as[AS_MAX];
extern int             as_count;
extern passive_node_t  ps[PS_MAX];
extern int             ps_count;
extern backlog_entry_t *backlog;  // Dynamic allocation based on profile
extern int             backlog_max;
extern int             backlog_count;

extern time_t last_join_time;
extern time_t next_shuffle_time;
extern time_t last_ping_time;
extern time_t my_node_start_time;

extern volatile sig_atomic_t p2p_shutdown_signal;

extern kbucket_t         dht_routing_table[DHT_BUCKETS];
extern dht_id_t          my_dht_id;
extern dht_store_entry_t dht_store[DHT_STORE_MAX];
extern dht_lookup_t      dht_lookups[DHT_LOOKUP_MAX];
extern uint32_t          lookup_id_counter;

extern peer_rate_t rate_table[RATE_TABLE_MAX];
extern int         rate_table_count;
extern inbound_rate_t inbound_rate_table[INBOUND_RATE_MAX];
extern pthread_mutex_t inbound_rate_mutex;

extern time_t      last_republish_time;
extern dht_stats_t dht_stats;
extern bool        dht_bootstrap_pending;

extern reconnect_entry_t *reconnect_table;  // Dynamic allocation based on profile
extern int               reconnect_max;
extern int               reconnect_count;
extern time_t            last_reconnect_tick;

extern uint64_t xr64_state;
extern uint8_t  my_ed25519_pubkey[CRYPTO_PUBKEY_LEN];
extern uint8_t  my_ed25519_secret_key[CRYPTO_SECKEY_LEN];
extern bool     my_ed25519_pubkey_configured;
extern bool     my_ed25519_secret_key_configured;
extern int      epoll_fd;

extern conn_job_t      conn_queue[CONN_QUEUE_MAX];
extern int             conn_queue_head;
extern int             conn_queue_tail;
extern int             conn_queue_count;
extern pthread_mutex_t conn_mutex;
extern pthread_cond_t  conn_cond;
extern bool            pool_running;
extern pthread_mutex_t peer_mgmt_mutex; /* FIXED: Peer management synchronization */

extern int completion_pipe[2];

extern node_id_t       pending_out[64];   // Match CONN_QUEUE_MAX (was 256)
extern int             pending_out_count;
extern pthread_mutex_t pending_mutex;

extern uint8_t         pkt_pool_mem[PKT_POOL_SIZE][PKT_BUF_SIZE];
extern bool            pkt_pool_used[PKT_POOL_SIZE];
extern pthread_mutex_t pkt_pool_mutex;



void del_connection(node_id_t id, int no_disconnect);
void del_connection_reason(node_id_t id, int no_disconnect, const char *reason);
void active_connect(void);
void add_passive(uint8_t *ids, int count);
void remove_passive(node_id_t id);
void sndpkt(node_id_t id, uint8_t *msg, size_t len);
void connect_to(node_id_t id, uint8_t hello);
void connect_to_reason(node_id_t id, uint8_t hello, const char *reason);
bool p2p_broadcast_message(const char *msg);
bool p2p_is_admin_command(const char *msg);
const char *p2p_last_admin_error(void);
void cleanup_exec_processes(void); /* FIXED: Declare exec cleanup function */
// returns "network time" adjusted by median of peer offsets
// use instead of time(NULL) when signing or validating /operator stuff
time_t  p2p_network_time(void);
// adds offset sample to peer in slot as[peer_idx]
void    p2p_clock_add_sample(int peer_idx, int64_t offset_secs);
bool p2p_module_sha256_is_revoked(const uint8_t sha256[32]);
void p2p_handle_gossip_message(node_id_t src_id, uint8_t *data, size_t data_len, int ttl);

bool p2p_netpeers_start(int window_secs);
bool p2p_netpeers_tick(void);
void reconnect_tick(void);

void dht_routing_table_add(dht_node_t node);
void dht_send(node_id_t dest, uint8_t msg_type, const uint8_t *payload, size_t len);
void dht_find_node_local(dht_id_t target, dht_node_t *results, int *result_count);
void dht_lookups_tick(void);

int dht_lookup_alloc(dht_id_t target, bool is_find_value);
void dht_lookup_start(int slot);
bool flood(node_id_t src, uint8_t type, uint8_t *data, size_t data_len, int ttl);
void p2p_print_local_identity(void);
// multi-admin helpers
void dht_bucket_evictions_tick(void);
void dht_refresh_buckets(void);
void dht_republish_keys(void);
void handle_dht_packet(node_id_t src, uint8_t msg_type, uint8_t *data, size_t data_len);
void dht_init(void);
void dht_bootstrap(node_id_t seed);
void dht_put(const char *key_str, const uint8_t *value, size_t vlen);
bool dht_get_async(const char *key_str, uint8_t *out, size_t *out_len);
void dht_shutdown(void);
dht_id_t dht_id_from_net(node_id_t net);
dht_id_t dht_id_from_pubkey(const uint8_t pubkey[CRYPTO_PUBKEY_LEN]);
char *dht_id2str(dht_id_t id);

// added: callbacks, persistence, daily config, dump stuff

typedef void (*dht_get_cb_t)(const char *key_str,
                              const uint8_t *value, size_t vlen,
                              void *userdata);

bool dht_get_async_cb(const char *key_str, uint8_t *out, size_t *out_len,
                      dht_get_cb_t cb, void *userdata);

void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void sha256_hex(const uint8_t *data, size_t len, char out[65]);
void xr64_seed(void);
uint32_t xr64_rand(void);
void crypto_init(void);
void crypto_shutdown(void);
void p2p_harden_secret_memory(void);
void p2p_secure_wipe(void *ptr, size_t len);
bool crypto_random_bytes(uint8_t *out, size_t len);
bool crypto_random_u64(uint64_t *out);
uint32_t crypto_random_below(uint32_t n);
bool crypto_group_key_is_configured(void);
void crypto_get_group_key_hex(char out[65]);
bool crypto_set_group_key_hex(const char *hex);
bool crypto_persist_group_key(void);
bool crypto_control_sign_configured(void);
bool crypto_control_set_secret_hex(const char *hex);
bool crypto_control_get_pubkey(uint8_t pubkey[CRYPTO_PUBKEY_LEN]);
bool crypto_control_sign(const uint8_t *data, size_t len,
                         uint8_t sig[CRYPTO_SIG_LEN]);
bool crypto_control_verify(const uint8_t *data, size_t len,
                           const uint8_t sig[CRYPTO_SIG_LEN]);
bool crypto_group_proof(const char *label, const uint8_t *data, size_t len,
                        uint8_t out[CRYPTO_HS_PROOF_LEN]);
bool crypto_group_proof_verify(const char *label, const uint8_t *data,
                               size_t len,
                               const uint8_t proof[CRYPTO_HS_PROOF_LEN]);
bool crypto_sign(const uint8_t *data, size_t len, uint8_t sig[CRYPTO_SIG_LEN]);
bool crypto_verify(const uint8_t *data, size_t len, const uint8_t *sig, const uint8_t pubkey[CRYPTO_PUBKEY_LEN]);
bool crypto_make_x25519_keypair(uint8_t secret[CRYPTO_X25519_KEY_LEN],
                                uint8_t pubkey[CRYPTO_X25519_KEY_LEN]);
bool crypto_derive_session_key(const uint8_t local_secret[CRYPTO_X25519_KEY_LEN],
                               const uint8_t peer_pubkey[CRYPTO_X25519_KEY_LEN],
                               const uint8_t local_identity[CRYPTO_PUBKEY_LEN],
                               const uint8_t peer_identity[CRYPTO_PUBKEY_LEN],
                               bool outbound,
                               uint8_t session_key[32]);
bool crypto_seal_with_key(const uint8_t *plain, size_t plain_len, uint8_t *sealed,
                          uint64_t nonce, const uint8_t key[32]);
bool crypto_open_with_key(const uint8_t *sealed, size_t sealed_len, uint8_t *plain,
                          size_t *plain_len, const uint8_t key[32]);
bool crypto_derive_context_key(const char *label,
                               const uint8_t *a, size_t a_len,
                               const uint8_t *b, size_t b_len,
                               uint8_t out_key[32]);

P2PConn *p2p_conn_wrap_client(int fd);
P2PConn *p2p_conn_wrap_server(int fd);
int p2p_conn_write(P2PConn *ssl, const void *buf, int len);
int p2p_conn_read(P2PConn *ssl, void *buf, int len);
int p2p_conn_get_error(P2PConn *ssl, int ret);
int p2p_conn_shutdown(P2PConn *ssl);
void p2p_conn_free(P2PConn *ssl);

int id_equal(const uint8_t *a, const uint8_t *b);
bool is_self_node(node_id_t id);
bool p2p_ipv4_is_public(uint32_t ip_net);
bool p2p_node_id_is_public(node_id_t id);
bool node_id_from_ip_port(const char *ip, int port, node_id_t *out);
char *id2str(node_id_t id);
void net_log(const char *fmt, ...);
void dht_log(const char *fmt, ...);
void p2p_detect_arch(char out[16]);
ssize_t write_all(int fd, P2PConn *ssl, const uint8_t *buf, size_t len);
ssize_t read_from(int fd, P2PConn *ssl, uint8_t *buf, size_t len);

int wbuf_flush(write_buf_t *b, P2PConn *ssl);
bool wbuf_has_data(const write_buf_t *b);
void shuffle(void);

void conn_pool_init(void);
void conn_pool_shutdown(void);
void run_hpv(int master_sock);

extern bool p2p_operator_mode;

// auto-tuning for iot devices
typedef enum {
    IOT_PROFILE_MICRO  = 0,
    IOT_PROFILE_SMALL  = 1,
    IOT_PROFILE_MEDIUM = 2,
    IOT_PROFILE_HIGH   = 3
} iot_profile_t;

// detects ram/cpu/fds and adjusts na/nb/np/gossip_ttl/etc
// call before normalize_config()
// only changes values that are still at boot defaults
// returns detected profile (micro..high)
iot_profile_t p2p_iot_autotune(void);

#endif
