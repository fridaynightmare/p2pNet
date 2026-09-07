#include "guard.h"

#define GUARD_WINDOW_SEC              60
#define GUARD_IP_BUCKET_MAX           2048   // Increased for large networks
#define GUARD_SUBNET_BUCKET_MAX       1024   // Increased for large networks
#define GUARD_TEMP_BAN_MAX            512    // Increased for large networks

#define GUARD_HANDSHAKES_PER_IP       12
#define GUARD_HANDSHAKES_PER_SUBNET   60
// GUARD_HANDSHAKES_GLOBAL removed - per-IP/subnet limits are sufficient
#define GUARD_DHT_STORES_GLOBAL       10000  // Increased for large networks
// GUARD_BROADCAST_GLOBAL removed - pressure detection handles this
// GUARD_BROADCAST_BYTES_GLOBAL removed - pressure detection handles this

#define GUARD_BAN_SECONDS             300

typedef struct {
    bool     used;
    uint32_t key;
    int      count;
    time_t   window_start;
} guard_bucket_t;

typedef struct {
    bool     used;
    uint32_t ip;
    time_t   until;
} guard_ban_t;

static guard_bucket_t ip_buckets[GUARD_IP_BUCKET_MAX];
static guard_bucket_t subnet_buckets[GUARD_SUBNET_BUCKET_MAX];
static guard_ban_t    temp_bans[GUARD_TEMP_BAN_MAX];
static pthread_mutex_t guard_mutex = PTHREAD_MUTEX_INITIALIZER;

// Removed global handshake/broadcast counters - per-IP/subnet limits are sufficient
static int    global_dht_stores = 0;
static time_t global_dht_window = 0;

static uint64_t guard_reject_banned = 0;
static uint64_t guard_reject_ip = 0;
static uint64_t guard_reject_subnet = 0;
// guard_reject_global removed
static uint64_t guard_reject_pressure = 0;
static uint64_t guard_reject_dht = 0;
static uint64_t guard_reject_broadcast = 0;

static uint32_t ip_key(const struct sockaddr_in *addr)
{
    return ntohl(addr->sin_addr.s_addr);
}

static uint32_t subnet24_key(uint32_t ip)
{
    return ip & 0xFFFFFF00u;
}

static bool bucket_allow(guard_bucket_t *buckets, int max_buckets,
                         uint32_t key, int limit, time_t now)
{
    int free_slot = -1;
    int oldest = 0;

    for (int i = 0; i < max_buckets; i++) {
        if (!buckets[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (buckets[i].window_start < buckets[oldest].window_start)
            oldest = i;
        if (buckets[i].key != key)
            continue;
        if (now - buckets[i].window_start > GUARD_WINDOW_SEC) {
            buckets[i].window_start = now;
            buckets[i].count = 1;
            return true;
        }
        if (buckets[i].count >= limit)
            return false;
        buckets[i].count++;
        return true;
    }

    int slot = (free_slot >= 0) ? free_slot : oldest;
    buckets[slot].used = true;
    buckets[slot].key = key;
    buckets[slot].count = 1;
    buckets[slot].window_start = now;
    return true;
}

static bool global_allow(int *count, time_t *window, int limit, time_t now)
{
    if (*window == 0 || now - *window > GUARD_WINDOW_SEC) {
        *window = now;
        *count = 1;
        return true;
    }
    if (*count >= limit)
        return false;
    (*count)++;
    return true;
}

static bool ban_active(uint32_t ip, time_t now)
{
    for (int i = 0; i < GUARD_TEMP_BAN_MAX; i++) {
        if (!temp_bans[i].used)
            continue;
        if (temp_bans[i].until <= now) {
            temp_bans[i].used = false;
            continue;
        }
        if (temp_bans[i].ip == ip)
            return true;
    }
    return false;
}

static void add_temp_ban(uint32_t ip, time_t now)
{
    int free_slot = -1;
    int oldest = 0;
    for (int i = 0; i < GUARD_TEMP_BAN_MAX; i++) {
        if (!temp_bans[i].used) {
            free_slot = i;
            break;
        }
        if (temp_bans[i].until < temp_bans[oldest].until)
            oldest = i;
    }
    int slot = (free_slot >= 0) ? free_slot : oldest;
    temp_bans[slot].used = true;
    temp_bans[slot].ip = ip;
    temp_bans[slot].until = now + GUARD_BAN_SECONDS;
}

static int dht_store_used(void)
{
    int used = 0;
    for (int i = 0; i < DHT_STORE_MAX; i++)
        if (dht_store[i].used)
            used++;
    return used;
}

bool p2p_guard_under_pressure(void)
{
    if (conn_queue_count >= (CONN_QUEUE_MAX * 2) / 3)
        return true;
    if (pending_out_count >= (CONN_QUEUE_MAX * 2) / 3)
        return true;
    if (as_count >= nb || as_count >= AS_MAX)
        return true;
    if (backlog_count >= (BL_MAX * 9) / 10)
        return true;
    if (dht_store_used() >= (DHT_STORE_MAX * 4) / 5)
        return true;
    return false;
}

bool p2p_guard_accept_inbound(const struct sockaddr_in *addr,
                              const char **reason)
{
    if (reason) *reason = "ok";
    if (!addr) {
        if (reason) *reason = "invalid_addr";
        return false;
    }

    time_t now = time(NULL);
    uint32_t ip = ip_key(addr);
    uint32_t subnet = subnet24_key(ip);

    pthread_mutex_lock(&guard_mutex);
    if (ban_active(ip, now)) {
        guard_reject_banned++;
        pthread_mutex_unlock(&guard_mutex);
        if (reason) *reason = "temp_ban";
        return false;
    }

    if (p2p_guard_under_pressure()) {
        guard_reject_pressure++;
        pthread_mutex_unlock(&guard_mutex);
        if (reason) *reason = "pressure";
        return false;
    }

    // Global handshake limit removed - per-IP/subnet limits are sufficient for DDoS protection
    // This allows networks to scale beyond 100k nodes

    if (!bucket_allow(ip_buckets, GUARD_IP_BUCKET_MAX, ip,
                      GUARD_HANDSHAKES_PER_IP, now)) {
        add_temp_ban(ip, now);
        guard_reject_ip++;
        pthread_mutex_unlock(&guard_mutex);
        if (reason) *reason = "ip_rate";
        return false;
    }

    if (!bucket_allow(subnet_buckets, GUARD_SUBNET_BUCKET_MAX, subnet,
                      GUARD_HANDSHAKES_PER_SUBNET, now)) {
        guard_reject_subnet++;
        pthread_mutex_unlock(&guard_mutex);
        if (reason) *reason = "subnet_rate";
        return false;
    }

    pthread_mutex_unlock(&guard_mutex);
    return true;
}

bool p2p_guard_allow_dht_store(node_id_t peer, const char **reason)
{
    (void)peer;
    if (reason) *reason = "ok";

    time_t now = time(NULL);
    pthread_mutex_lock(&guard_mutex);
    if (p2p_guard_under_pressure()) {
        guard_reject_dht++;
        pthread_mutex_unlock(&guard_mutex);
        if (reason) *reason = "pressure";
        return false;
    }
    if (!global_allow(&global_dht_stores, &global_dht_window,
                      GUARD_DHT_STORES_GLOBAL, now)) {
        guard_reject_dht++;
        pthread_mutex_unlock(&guard_mutex);
        if (reason) *reason = "global_store_rate";
        return false;
    }
    pthread_mutex_unlock(&guard_mutex);
    return true;
}

bool p2p_guard_allow_broadcast(size_t payload_len, int ttl,
                               const char **reason)
{
    if (reason) *reason = "ok";
    if (payload_len > HPV_PKT_MAX || ttl > P2P_BROADCAST_TTL_MAX) {
        if (reason) *reason = "invalid_broadcast";
        return false;
    }

    time_t now = time(NULL);
    pthread_mutex_lock(&guard_mutex);
    if (p2p_guard_under_pressure()) {
        guard_reject_broadcast++;
        pthread_mutex_unlock(&guard_mutex);
        if (reason) *reason = "pressure";
        return false;
    }

    // Global broadcast limit removed - pressure detection is sufficient
    // This allows networks to scale beyond 100k nodes while still protecting
    // individual nodes from overload via pressure detection

    pthread_mutex_unlock(&guard_mutex);
    return true;
}

void p2p_guard_dump_status(void)
{
    pthread_mutex_lock(&guard_mutex);
    printf("pressure=%s cq=%d/%d pend=%d/%d act=%d/%d dht=%d/%d\n",
           p2p_guard_under_pressure() ? "yes" : "no",
           conn_queue_count, CONN_QUEUE_MAX,
           pending_out_count, CONN_QUEUE_MAX,
           as_count, nb,
           dht_store_used(), DHT_STORE_MAX);
    printf("broadcast ttl=%d fan=%d (no global limit)\n",
           P2P_BROADCAST_TTL_MAX, P2P_BROADCAST_FANOUT_MAX);
    printf("rejects: ban=%llu ip=%llu sub=%llu pres=%llu dht=%llu bcast=%llu\n",
           (unsigned long long)guard_reject_banned,
           (unsigned long long)guard_reject_ip,
           (unsigned long long)guard_reject_subnet,
           (unsigned long long)guard_reject_pressure,
           (unsigned long long)guard_reject_dht,
           (unsigned long long)guard_reject_broadcast);
    pthread_mutex_unlock(&guard_mutex);
}
