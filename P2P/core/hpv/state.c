#include "common.h"

int join_interval     = 60;
int arwl              = 3;
int prwl              = 8;
int mrwl              = 30;
int n0                = 2;
int na                = 10;
int ka                = 2;
int kp                = 4;
int nb                = 25;
int np                = 200;
int shuffle0          = 60;
int shuffle1          = 120;
int my_listen_port    = P2P_DEFAULT_PORT;
char my_arch[16] = "Unknown";
int gossip_ttl        = P2P_DEFAULT_GOSSIP_TTL;
int overlay_max_sessions = 16;  // Default, adjusted by IoT profile



active_node_t  *as[AS_MAX];
int             as_count = 0;
passive_node_t  ps[PS_MAX];
int             ps_count = 0;
backlog_entry_t *backlog = NULL;      // Allocated dynamically based on profile
int             backlog_max = 0;
int             backlog_count = 0;

time_t last_join_time    = 0;
time_t next_shuffle_time = 0;
time_t last_ping_time    = 0;

time_t my_node_start_time   = 0;

volatile sig_atomic_t p2p_shutdown_signal = 0;

kbucket_t         dht_routing_table[DHT_BUCKETS];
dht_id_t          my_dht_id;
dht_store_entry_t dht_store[DHT_STORE_MAX];
dht_lookup_t      dht_lookups[DHT_LOOKUP_MAX];
uint32_t   lookup_id_counter = 0;

#define RATE_TABLE_MAX 64
peer_rate_t rate_table[RATE_TABLE_MAX];
int         rate_table_count = 0;
inbound_rate_t inbound_rate_table[INBOUND_RATE_MAX];
pthread_mutex_t inbound_rate_mutex = PTHREAD_MUTEX_INITIALIZER;

time_t      last_republish_time = 0;
dht_stats_t dht_stats           = {0};
bool dht_bootstrap_pending = false;

reconnect_entry_t *reconnect_table = NULL;  // Allocated dynamically based on profile
int               reconnect_max = 0;
int               reconnect_count     = 0;
time_t            last_reconnect_tick = 0;

uint64_t xr64_state;

uint8_t   my_ed25519_pubkey[CRYPTO_PUBKEY_LEN];
uint8_t   my_ed25519_secret_key[CRYPTO_SECKEY_LEN];
bool      my_ed25519_pubkey_configured = false;
bool      my_ed25519_secret_key_configured = false;

int epoll_fd = -1;

conn_job_t      conn_queue[CONN_QUEUE_MAX];
int             conn_queue_head  = 0;
int             conn_queue_tail  = 0;
int             conn_queue_count = 0;
pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  conn_cond  = PTHREAD_COND_INITIALIZER;
bool            pool_running = true;

int completion_pipe[2];

node_id_t pending_out[CONN_QUEUE_MAX];
int       pending_out_count = 0;
pthread_mutex_t pending_mutex = PTHREAD_MUTEX_INITIALIZER;

uint8_t        pkt_pool_mem[PKT_POOL_SIZE][PKT_BUF_SIZE];
bool           pkt_pool_used[PKT_POOL_SIZE];
pthread_mutex_t pkt_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
