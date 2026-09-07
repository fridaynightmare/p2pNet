#include "common.h"
#include "guard.h"
#include "dht_serialize.h"

// dht stuff - all in ram cause persistence wasnt implemented yet

// function declarations - put them here or compiler complains
int  dht_lookup_alloc(dht_id_t target, bool is_find_value);
void dht_lookup_start(int slot);
static void dht_lookup_continue(int slot);
static void dht_lookup_finish(int slot);
static void dht_hash_id(const uint8_t *data, size_t len, uint8_t out[DHT_ID_BYTES]);
static void dht_lookup_on_found_nodes(uint32_t lid, node_id_t from,
                                       dht_node_t *nodes, int count);
static void dht_lookup_on_found_value(uint32_t lid, dht_id_t key,
                                       const uint8_t *val, size_t vlen);
static void dht_bucket_ping_oldest(int bucket_idx, dht_node_t candidate);
static void dht_bucket_on_pong(dht_id_t id);
static void dht_shortlist_sort(dht_lookup_t *lk);
static void dht_store_local(dht_id_t key, const uint8_t *value,
                             size_t vlen, uint32_t ttl);
static bool dht_lookup_local(dht_id_t key, uint8_t *out, size_t *out_len);
static void dht_node_record_failure(dht_id_t id);
static void dht_node_record_success(dht_id_t id);
static void dht_routing_table_remove_endpoint(node_id_t endpoint,
                                               const dht_id_t *keep_id);
static size_t dht_serialize_nodes(const dht_node_t *nodes, int count,
                                   uint8_t *out, size_t out_max);
static int dht_deserialize_nodes(const uint8_t *buf, size_t len,
                                  dht_node_t *out, int max_out);

// callbacks for dht_get
// used to return nothing, now you get callback when its done
// because apparently we need to know when lookups finish

#define DHT_CB_KEY_MAX 128

typedef void (*dht_get_cb_t)(const char *key_str,
                              const uint8_t *value, size_t vlen,
                              void *userdata);

typedef struct {
    bool         used;
    uint32_t     lookup_id;           /* lookup it's associated with */
    char         key_str[DHT_CB_KEY_MAX];
    dht_get_cb_t cb;
    void        *userdata;
} dht_pending_cb_t;

static dht_pending_cb_t dht_pending_cbs[DHT_LOOKUP_MAX];

// register callback for lookup
static void dht_cb_register(int slot, const char *key_str,
                             dht_get_cb_t cb, void *userdata)
{
    if (!cb) return;
    for (int i = 0; i < DHT_LOOKUP_MAX; i++) {
        if (dht_pending_cbs[i].used) continue;
        dht_pending_cbs[i].used      = true;
        dht_pending_cbs[i].lookup_id = dht_lookups[slot].lookup_id;
        snprintf(dht_pending_cbs[i].key_str,
                 sizeof(dht_pending_cbs[i].key_str), "%s", key_str);
        dht_pending_cbs[i].cb        = cb;
        dht_pending_cbs[i].userdata  = userdata;
        return;
    }
    dht_log("dht_cb_register: callback table full");
}

// fire callback when value found
static void dht_cb_fire(uint32_t lookup_id, dht_id_t target,
                         const uint8_t *value, size_t vlen)
{
    for (int i = 0; i < DHT_LOOKUP_MAX; i++) {
        if (!dht_pending_cbs[i].used) continue;
        if (dht_pending_cbs[i].lookup_id != lookup_id) continue;

        // check callback key matches what we got
        uint8_t digest[32];
        sha256((const uint8_t *)dht_pending_cbs[i].key_str,
               strlen(dht_pending_cbs[i].key_str), digest);
        if (memcmp(digest, target.bytes, DHT_ID_BYTES) != 0) continue;

        dht_pending_cbs[i].cb(dht_pending_cbs[i].key_str,
                              value, vlen,
                              dht_pending_cbs[i].userdata);
        dht_pending_cbs[i].used = false;
        return;
    }
}

// dht implementation

static bool dht_net_peer_is_active(node_id_t id)
{
    for (int i = 0; i < as_count; i++) {
        if (id_equal(as[i]->id.id, id.id))
            return true;
    }
    return false;
}

static bool dht_endpoint_is_valid(node_id_t id)
{
    uint16_t port;
    memcpy(&port, id.id + 4, 2);
    if (port == 0) return false;
    if (is_self_node(id)) return false;
    if (!p2p_node_id_is_public(id)) return false;
    return true;
}

static bool dht_node_is_usable(dht_node_t node)
{
    if (memcmp(node.dht_id.bytes, my_dht_id.bytes, DHT_ID_BYTES) == 0)
        return false;
    return dht_endpoint_is_valid(node.net_id);
}

static bool dht_node_is_queryable(dht_node_t node)
{
    return dht_node_is_usable(node) && dht_net_peer_is_active(node.net_id);
}

static void dht_note_candidate_endpoint(node_id_t id)
{
    if (!dht_endpoint_is_valid(id)) return;
    add_passive(id.id, 1);
    if (as_count < n0)
        connect_to_reason(id, H_NEIGHBOR_LO, "dht-discovery");
}

static void dht_bucket_remove_slot(kbucket_t *kb, int slot)
{
    if (slot < 0 || slot >= kb->count) return;
    memmove(&kb->entries[slot], &kb->entries[slot+1],
            sizeof(dht_node_t)*(size_t)(kb->count-slot-1));
    memmove(&kb->stats[slot], &kb->stats[slot+1],
            sizeof(dht_node_stats_t)*(size_t)(kb->count-slot-1));
    kb->count--;
    if (kb->has_pending) {
        if (kb->ping_slot == slot) kb->has_pending = false;
        else if (kb->ping_slot > slot) kb->ping_slot--;
    }
}

static int dht_routing_table_prune_inactive(void)
{
    int removed = 0;
    for (int b = 0; b < DHT_BUCKETS; b++) {
        kbucket_t *kb = &dht_routing_table[b];
        for (int i = 0; i < kb->count; ) {
            if (dht_node_is_usable(kb->entries[i]) &&
                (dht_net_peer_is_active(kb->entries[i].net_id) ||
                 kb->stats[i].failures < DHT_FAILURE_THRESHOLD)) {
                i++;
                continue;
            }
            dht_bucket_remove_slot(kb, i);
            kb->last_changed = time(NULL);
            removed++;
        }
    }
    return removed;
}

static void dht_hash_id(const uint8_t *data, size_t len,
                        uint8_t out[DHT_ID_BYTES])
{
    uint8_t digest[32];
    sha256(data, len, digest);
    memcpy(out, digest, DHT_ID_BYTES);
    p2p_secure_wipe(digest, sizeof(digest));
}

dht_id_t dht_id_from_net(node_id_t net)
{
    dht_id_t id;
    dht_hash_id(net.id, 6, id.bytes);
    return id;
}

dht_id_t dht_id_from_pubkey(const uint8_t pubkey[CRYPTO_PUBKEY_LEN])
{
    dht_id_t id;
    dht_hash_id(pubkey, CRYPTO_PUBKEY_LEN, id.bytes);
    return id;
}

static void dht_init_my_id(void)
{
    if (my_ed25519_pubkey_configured) {
        my_dht_id = dht_id_from_pubkey(my_ed25519_pubkey);
        return;
    }
    if (!crypto_random_bytes(my_dht_id.bytes, DHT_ID_BYTES))
        dht_log("strong RNG not available for DHT ID; using non-cryptographic fallback");
}

char *dht_id2str(dht_id_t id)
{
    static char pool[16][48];
    static int  slot = 0;
    char *s = pool[slot & 15]; slot++;
    for (int i = 0; i < 8; i++)
        snprintf(s + i*2, 3, "%02x", id.bytes[i]);
    s[16] = '\0';
    return s;
}

static void dht_xor_distance(const dht_id_t *a, const dht_id_t *b,
                              uint8_t out[DHT_ID_BYTES])
{
    for (int i = 0; i < DHT_ID_BYTES; i++)
        out[i] = a->bytes[i] ^ b->bytes[i];
}

static int dht_cmp_dist(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, DHT_ID_BYTES);
}

static int dht_bucket_index(const uint8_t dist[DHT_ID_BYTES])
{
    for (int byte = 0; byte < DHT_ID_BYTES; byte++) {
        if (dist[byte] == 0) continue;
        for (int bit = 7; bit >= 0; bit--)
            if (dist[byte] & (1 << bit))
                return byte * 8 + (7 - bit);
    }
    return -1;
}

static void dht_bucket_ping_oldest(int bucket_idx, dht_node_t candidate)
{
    kbucket_t *kb = &dht_routing_table[bucket_idx];
    if (kb->has_pending) return;
    if (!dht_node_is_queryable(candidate)) {
        dht_note_candidate_endpoint(candidate.net_id);
        return;
    }
    if (kb->count > 0 && !dht_net_peer_is_active(kb->entries[0].net_id)) {
        dht_bucket_remove_slot(kb, 0);
        dht_routing_table_add(candidate);
        return;
    }
    if (kb->count == 0) return;
    kb->pending      = candidate;
    kb->has_pending  = true;
    kb->ping_sent_at = time(NULL);
    kb->ping_slot    = 0;
    dht_send(kb->entries[0].net_id, M_DHT_PING, my_dht_id.bytes, DHT_ID_BYTES);
    dht_stats.total_pings_sent++;
}

static void dht_bucket_on_pong(dht_id_t id)
{
    for (int b = 0; b < DHT_BUCKETS; b++) {
        kbucket_t *kb = &dht_routing_table[b];
        if (!kb->has_pending) continue;
        if (kb->ping_slot < 0 || kb->ping_slot >= kb->count) {
            kb->has_pending = false; continue;
        }
        if (memcmp(kb->entries[kb->ping_slot].dht_id.bytes,
                   id.bytes, DHT_ID_BYTES) != 0) continue;

        dht_node_t       old  = kb->entries[kb->ping_slot];
        dht_node_stats_t olds = kb->stats[kb->ping_slot];
        int slot = kb->ping_slot;
        memmove(&kb->entries[slot], &kb->entries[slot+1],
                sizeof(dht_node_t)*(size_t)(kb->count-slot-1));
        memmove(&kb->stats[slot], &kb->stats[slot+1],
                sizeof(dht_node_stats_t)*(size_t)(kb->count-slot-1));
        kb->entries[kb->count-1]            = old;
        kb->stats[kb->count-1]              = olds;
        kb->stats[kb->count-1].last_seen    = time(NULL);
        kb->stats[kb->count-1].failures     = 0;
        kb->has_pending = false;
        return;
    }
}

void dht_routing_table_add(dht_node_t node)
{
    dht_routing_table_prune_inactive();
    if (!dht_node_is_usable(node)) return;
    if (!dht_net_peer_is_active(node.net_id))
        dht_note_candidate_endpoint(node.net_id);
    dht_routing_table_remove_endpoint(node.net_id, &node.dht_id);

    uint8_t dist[DHT_ID_BYTES];
    dht_xor_distance(&my_dht_id, &node.dht_id, dist);
    int bucket = dht_bucket_index(dist);
    if (bucket < 0) return;

    kbucket_t *kb = &dht_routing_table[bucket];

    for (int i = 0; i < kb->count; i++) {
        if (memcmp(kb->entries[i].dht_id.bytes,
                   node.dht_id.bytes, DHT_ID_BYTES) == 0) {
            dht_node_t       tmp_n = kb->entries[i];
            dht_node_stats_t tmp_s = kb->stats[i];
            memmove(&kb->entries[i], &kb->entries[i+1],
                    sizeof(dht_node_t)*(size_t)(kb->count-i-1));
            memmove(&kb->stats[i], &kb->stats[i+1],
                    sizeof(dht_node_stats_t)*(size_t)(kb->count-i-1));
            kb->entries[kb->count-1]         = tmp_n;
            kb->stats[kb->count-1]           = tmp_s;
            kb->stats[kb->count-1].last_seen = time(NULL);
            kb->last_changed = time(NULL);
            return;
        }
    }

    if (kb->count < DHT_K) {
        kb->entries[kb->count] = node;
        memset(&kb->stats[kb->count], 0, sizeof(dht_node_stats_t));
        kb->stats[kb->count].last_seen = time(NULL);
        kb->count++;
        kb->last_changed = time(NULL);
    } else {
        dht_bucket_ping_oldest(bucket, node);
    }
}

static void dht_routing_table_remove(dht_id_t id)
{
    uint8_t dist[DHT_ID_BYTES];
    dht_xor_distance(&my_dht_id, &id, dist);
    int bucket = dht_bucket_index(dist);
    if (bucket < 0) return;

    kbucket_t *kb = &dht_routing_table[bucket];
    for (int i = 0; i < kb->count; i++) {
        if (memcmp(kb->entries[i].dht_id.bytes, id.bytes, DHT_ID_BYTES) == 0) {
            dht_bucket_remove_slot(kb, i);
            return;
        }
    }
}

static void dht_routing_table_remove_endpoint(node_id_t endpoint,
                                               const dht_id_t *keep_id)
{
    for (int b = 0; b < DHT_BUCKETS; b++) {
        kbucket_t *kb = &dht_routing_table[b];
        for (int i = 0; i < kb->count; ) {
            if (!id_equal(kb->entries[i].net_id.id, endpoint.id)) {
                i++;
                continue;
            }
            if (keep_id &&
                memcmp(kb->entries[i].dht_id.bytes, keep_id->bytes,
                       DHT_ID_BYTES) == 0) {
                i++;
                continue;
            }
            dht_bucket_remove_slot(kb, i);
            kb->last_changed = time(NULL);
        }
    }
}

static void dht_node_record_failure(dht_id_t id)
{
    uint8_t dist[DHT_ID_BYTES];
    dht_xor_distance(&my_dht_id, &id, dist);
    int bucket = dht_bucket_index(dist);
    if (bucket < 0) return;

    kbucket_t *kb = &dht_routing_table[bucket];
    for (int i = 0; i < kb->count; i++) {
        if (memcmp(kb->entries[i].dht_id.bytes, id.bytes, DHT_ID_BYTES) == 0) {
            kb->stats[i].failures++;
            kb->stats[i].last_failure = time(NULL);
            if (kb->stats[i].failures >= DHT_FAILURE_THRESHOLD) {
                if (dht_net_peer_is_active(kb->entries[i].net_id)) {
                    kb->stats[i].failures = DHT_FAILURE_THRESHOLD - 1;
                    dht_log("node %s has active tcp; keeping despite dht fails",
                            dht_id2str(id));
                    return;
                }
                dht_log("node %s removed after hitting failure threshold",
                        dht_id2str(id));
                dht_routing_table_remove(id);
            }
            return;
        }
    }
}

static void dht_node_record_success(dht_id_t id)
{
    uint8_t dist[DHT_ID_BYTES];
    dht_xor_distance(&my_dht_id, &id, dist);
    int bucket = dht_bucket_index(dist);
    if (bucket < 0) return;

    kbucket_t *kb = &dht_routing_table[bucket];
    for (int i = 0; i < kb->count; i++) {
        if (memcmp(kb->entries[i].dht_id.bytes, id.bytes, DHT_ID_BYTES) == 0) {
            kb->stats[i].successes++;
            kb->stats[i].last_seen = time(NULL);
            kb->stats[i].failures  = 0;
            return;
        }
    }
}

void dht_bucket_evictions_tick(void)
{
    static time_t last_evict_log = 0;
    time_t now = time(NULL);
    dht_routing_table_prune_inactive();
    for (int b = 0; b < DHT_BUCKETS; b++) {
        kbucket_t *kb = &dht_routing_table[b];
        if (!kb->has_pending) continue;
        if (now - kb->ping_sent_at < DHT_QUERY_TIMEOUT) continue;

        int        slot      = kb->ping_slot;
        dht_node_t candidate = kb->pending;
        kb->has_pending = false;

        if (slot < 0 || slot >= kb->count) {
            dht_routing_table_add(candidate); continue;
        }
        /* log removed: normal during bootstrap and on local networks */
        (void)last_evict_log;
        dht_bucket_remove_slot(kb, slot);
        kb->last_changed = now;
        if (dht_node_is_usable(candidate))
            dht_routing_table_add(candidate);
    }
}

static int cmp_node_by_xor_dist_r(const void *a, const void *b, void *arg)
{
    const dht_id_t *tgt = (const dht_id_t *)arg;
    uint8_t da[DHT_ID_BYTES], db[DHT_ID_BYTES];
    dht_xor_distance(tgt, &((const dht_node_t *)a)->dht_id, da);
    dht_xor_distance(tgt, &((const dht_node_t *)b)->dht_id, db);
    return dht_cmp_dist(da, db);
}

void dht_find_node_local(dht_id_t target, dht_node_t *results, int *result_count)
{
    dht_routing_table_prune_inactive();
    dht_node_t *all = malloc(sizeof(dht_node_t) * DHT_BUCKETS * DHT_K);
    if (!all) { *result_count = 0; return; }

    int total = 0;
    for (int b = 0; b < DHT_BUCKETS; b++) {
        kbucket_t *kb = &dht_routing_table[b];
        for (int i = 0; i < kb->count; i++) {
            if (kb->stats[i].failures >= DHT_FAILURE_THRESHOLD) continue;
            if (!dht_node_is_usable(kb->entries[i])) continue;
            all[total++] = kb->entries[i];
        }
    }

    qsort_r(all, (size_t)total, sizeof(dht_node_t),
            cmp_node_by_xor_dist_r, &target);

    *result_count = (total < DHT_K) ? total : DHT_K;
    memcpy(results, all, sizeof(dht_node_t)*(size_t)(*result_count));
    free(all);
}

static void dht_store_local(dht_id_t key, const uint8_t *value,
                             size_t vlen, uint32_t ttl)
{
    if (vlen > DHT_VALUE_MAX) vlen = DHT_VALUE_MAX;
    if (ttl == 0) ttl = DHT_TTL;
    time_t now = time(NULL);

    for (int i = 0; i < DHT_STORE_MAX; i++) {
        if (!dht_store[i].used) continue;
        if (memcmp(dht_store[i].key.bytes, key.bytes, DHT_ID_BYTES) == 0) {
            memcpy(dht_store[i].value, value, vlen);
            dht_store[i].value_len = vlen;
            dht_store[i].expire    = now + (time_t)ttl;
            return;
        }
    }
    for (int i = 0; i < DHT_STORE_MAX; i++) {
        if (!dht_store[i].used || dht_store[i].expire < now) {
            dht_store[i].key        = key;
            memcpy(dht_store[i].value, value, vlen);
            dht_store[i].value_len  = vlen;
            dht_store[i].expire     = now + (time_t)ttl;
            dht_store[i].stored_at  = now;
            dht_store[i].used       = true;
            dht_stats.total_stores++;
            return;
        }
    }
    dht_log("local store full; entry dropped");
}

static bool dht_lookup_local(dht_id_t key, uint8_t *out, size_t *out_len)
{
    time_t now = time(NULL);
    for (int i = 0; i < DHT_STORE_MAX; i++) {
        if (!dht_store[i].used) continue;
        if (dht_store[i].expire < now) { dht_store[i].used = false; continue; }
        if (memcmp(dht_store[i].key.bytes, key.bytes, DHT_ID_BYTES) == 0) {
            if (out)     memcpy(out, dht_store[i].value, dht_store[i].value_len);
            if (out_len) *out_len = dht_store[i].value_len;
            return true;
        }
    }
    return false;
}

static bool dht_rate_check_store(node_id_t peer)
{
    time_t now = time(NULL);
    for (int i = 0; i < rate_table_count; i++) {
        if (!id_equal(rate_table[i].peer.id, peer.id)) continue;
        if (now - rate_table[i].window_start > 60) {
            rate_table[i].store_count  = 1;
            rate_table[i].window_start = now;
            return true;
        }
        if (rate_table[i].store_count >= DHT_STORE_RATE_MAX) {
            dht_log("rate limit STORE from %s (%d/min)", id2str(peer),
                    rate_table[i].store_count);
            return false;
        }
        rate_table[i].store_count++;
        return true;
    }
    if (rate_table_count < RATE_TABLE_MAX) {
        rate_table[rate_table_count].peer         = peer;
        rate_table[rate_table_count].store_count  = 1;
        rate_table[rate_table_count].window_start = now;
        rate_table_count++;
    } else {
        int oldest = 0;
        for (int i = 1; i < rate_table_count; i++)
            if (rate_table[i].window_start < rate_table[oldest].window_start)
                oldest = i;
        rate_table[oldest].peer         = peer;
        rate_table[oldest].store_count  = 1;
        rate_table[oldest].window_start = now;
    }
    return true;
}

static void dht_shortlist_sort(dht_lookup_t *lk)
{
    for (int i = 1; i < lk->shortlist_count; i++) {
        dht_node_t tn = lk->shortlist[i];
        uint8_t    td[DHT_ID_BYTES];
        memcpy(td, lk->dist[i], DHT_ID_BYTES);
        bool   tq = lk->queried[i];
        bool   tr = lk->responded[i];
        bool   tf = lk->failed[i];
        time_t tt = lk->query_time[i];

        int j = i;
        while (j > 0 && dht_cmp_dist(lk->dist[j-1], td) > 0) {
            lk->shortlist[j]  = lk->shortlist[j-1];
            memcpy(lk->dist[j], lk->dist[j-1], DHT_ID_BYTES);
            lk->queried[j]    = lk->queried[j-1];
            lk->responded[j]  = lk->responded[j-1];
            lk->failed[j]     = lk->failed[j-1];
            lk->query_time[j] = lk->query_time[j-1];
            j--;
        }
        lk->shortlist[j]  = tn;
        memcpy(lk->dist[j], td, DHT_ID_BYTES);
        lk->queried[j]    = tq;
        lk->responded[j]  = tr;
        lk->failed[j]     = tf;
        lk->query_time[j] = tt;
    }
}

static bool dht_shortlist_insert(dht_lookup_t *lk, dht_node_t node)
{
    if (!dht_node_is_usable(node)) return false;

    uint8_t dist[DHT_ID_BYTES];
    dht_xor_distance(&lk->target, &node.dht_id, dist);

    for (int i = 0; i < lk->shortlist_count; i++)
        if (memcmp(lk->shortlist[i].dht_id.bytes,
                   node.dht_id.bytes, DHT_ID_BYTES) == 0)
            return false;

    if (lk->shortlist_count < DHT_SHORTLIST_MAX) {
        int pos = lk->shortlist_count;
        lk->shortlist[pos]  = node;
        memcpy(lk->dist[pos], dist, DHT_ID_BYTES);
        lk->queried[pos]    = false;
        lk->responded[pos]  = false;
        lk->failed[pos]     = false;
        lk->query_time[pos] = 0;
        lk->shortlist_count++;
    } else {
        int worst = 0;
        for (int i = 1; i < lk->shortlist_count; i++)
            if (dht_cmp_dist(lk->dist[i], lk->dist[worst]) > 0) worst = i;
        if (dht_cmp_dist(dist, lk->dist[worst]) >= 0) return false;
        lk->shortlist[worst]  = node;
        memcpy(lk->dist[worst], dist, DHT_ID_BYTES);
        lk->queried[worst]    = false;
        lk->responded[worst]  = false;
        lk->failed[worst]     = false;
        lk->query_time[worst] = 0;
    }
    dht_shortlist_sort(lk);
    return true;
}

int dht_lookup_alloc(dht_id_t target, bool is_find_value)
{
    static time_t last_pool_full_log = 0;
    for (int i = 0; i < DHT_LOOKUP_MAX; i++) {
        if (dht_lookups[i].active) continue;
        memset(&dht_lookups[i], 0, sizeof(dht_lookup_t));
        dht_lookups[i].active        = true;
        dht_lookups[i].is_find_value = is_find_value;
        dht_lookups[i].target        = target;
        dht_lookups[i].start_time    = time(NULL);
        dht_lookups[i].lookup_id     = ++lookup_id_counter;
        dht_stats.lookups_active++;
        dht_stats.total_lookups++;
        return i;
    }
    time_t now = time(NULL);
    if (now - last_pool_full_log >= 10) {
        dht_log("lookup pool full");
        last_pool_full_log = now;
    }
    return -1;
}

void dht_lookup_start(int slot)
{
    dht_lookup_t *lk = &dht_lookups[slot];
    dht_node_t seed[DHT_K];
    int seed_count = 0;
    dht_find_node_local(lk->target, seed, &seed_count);
    for (int i = 0; i < seed_count; i++)
        dht_shortlist_insert(lk, seed[i]);
    if (lk->shortlist_count == 0) {
        dht_log("lookup %u no seed nodes, aborting", lk->lookup_id);
        dht_lookup_finish(slot); return;
    }
    dht_lookup_continue(slot);
}

static void dht_lookup_continue(int slot)
{
    dht_lookup_t *lk = &dht_lookups[slot];
    if (lk->finished) return;
    time_t now = time(NULL);

    for (int i = 0; i < lk->shortlist_count; i++) {
        if (lk->queried[i] && !lk->responded[i] && !lk->failed[i]) {
            if (now - lk->query_time[i] > DHT_QUERY_TIMEOUT) {
                lk->failed[i] = true;
                lk->active_queries--;
                if (lk->active_queries < 0) lk->active_queries = 0;
                dht_node_record_failure(lk->shortlist[i].dht_id);
            }
        }
    }

    int sent = 0;
    for (int i = 0; i < lk->shortlist_count && sent < DHT_ALPHA; i++) {
        if (lk->active_queries >= DHT_ALPHA) break;
        if (lk->queried[i]) continue;
        if (!dht_node_is_queryable(lk->shortlist[i])) {
            dht_note_candidate_endpoint(lk->shortlist[i].net_id);
            lk->queried[i] = true;
            lk->failed[i] = true;
            continue;
        }

        uint8_t payload[24];
        dht_msgbuf_t msg;
        dht_msgbuf_init(&msg, payload, sizeof(payload));
        dht_msgbuf_append_u32(&msg, lk->lookup_id);
        dht_msgbuf_append(&msg, lk->target.bytes, DHT_ID_BYTES);

        uint8_t msg_type = lk->is_find_value ? M_DHT_FIND_VALUE : M_DHT_FIND_NODE;
        dht_send(lk->shortlist[i].net_id, msg_type, 
                 dht_msgbuf_data(&msg), dht_msgbuf_size(&msg));

        lk->queried[i]    = true;
        lk->query_time[i] = now;
        lk->active_queries++;
        sent++;
    }

    bool has_unqueried = false;
    for (int i = 0; i < lk->shortlist_count && i < DHT_K; i++)
        if (!lk->queried[i]) has_unqueried = true;
    if (!has_unqueried && lk->active_queries == 0)
        dht_lookup_finish(slot);
}

/* altered: fires callback if value found */
static void dht_lookup_finish(int slot)
{
    dht_lookup_t *lk = &dht_lookups[slot];
    if (!lk->active) return;
    double elapsed = (double)(time(NULL) - lk->start_time) * 1000.0;
    if (lk->value_found) {
        dht_stats.successful_lookups++;
        dht_log("lookup %u done (VALUE) in %.0f ms", lk->lookup_id, elapsed);
        /* fire callback */
        dht_cb_fire(lk->lookup_id, lk->target,
                    lk->found_value, lk->found_value_len);
    } else {
        dht_log("lookup %u done (%d nodes) in %.0f ms",
                lk->lookup_id, lk->shortlist_count, elapsed);
    }
    uint64_t n = dht_stats.total_lookups;
    if (n > 0)
        dht_stats.lookup_latency_avg_ms =
            (dht_stats.lookup_latency_avg_ms * (double)(n-1) + elapsed) / (double)n;
    lk->active = false;
    dht_stats.lookups_active--;
    if (dht_stats.lookups_active < 0) dht_stats.lookups_active = 0;
}

static void dht_lookup_on_found_nodes(uint32_t lid, node_id_t from,
                                       dht_node_t *nodes, int count)
{
    for (int s = 0; s < DHT_LOOKUP_MAX; s++) {
        dht_lookup_t *lk = &dht_lookups[s];
        if (!lk->active || lk->lookup_id != lid) continue;

        dht_id_t from_dht = dht_id_from_net(from);
        for (int i = 0; i < lk->shortlist_count; i++) {
            if (memcmp(lk->shortlist[i].dht_id.bytes,
                       from_dht.bytes, DHT_ID_BYTES) == 0) {
                if (!lk->responded[i]) {
                    lk->responded[i] = true;
                    lk->active_queries--;
                    if (lk->active_queries < 0) lk->active_queries = 0;
                    dht_node_record_success(from_dht);
                }
                break;
            }
        }
        for (int i = 0; i < count; i++) {
            if (dht_shortlist_insert(lk, nodes[i]))
                dht_routing_table_add(nodes[i]);
        }
        dht_lookup_continue(s);
        return;
    }
}

static void dht_lookup_on_found_value(uint32_t lid, dht_id_t key,
                                       const uint8_t *val, size_t vlen)
{
    for (int s = 0; s < DHT_LOOKUP_MAX; s++) {
        dht_lookup_t *lk = &dht_lookups[s];
        if (!lk->active || !lk->is_find_value || lk->lookup_id != lid) continue;
        if (memcmp(lk->target.bytes, key.bytes, DHT_ID_BYTES) != 0) continue;

        if (vlen > DHT_VALUE_MAX) vlen = DHT_VALUE_MAX;
        memcpy(lk->found_value, val, vlen);
        lk->found_value_len = vlen;
        lk->value_found     = true;
        dht_store_local(key, val, vlen, DHT_TTL / 2);
        dht_lookup_finish(s);
        return;
    }
}

void dht_lookups_tick(void)
{
    time_t now = time(NULL);
    for (int s = 0; s < DHT_LOOKUP_MAX; s++) {
        dht_lookup_t *lk = &dht_lookups[s];
        if (!lk->active) continue;
        dht_lookup_continue(s);
        if (now - lk->start_time > DHT_LOOKUP_TIMEOUT) {
            dht_log("lookup %u global timeout, aborting", lk->lookup_id);
            dht_lookup_finish(s);
        }
    }
}

static void dht_refresh_bucket(int b)
{
    kbucket_t *kb = &dht_routing_table[b];
    kb->last_changed = time(NULL);

    dht_id_t rand_id = my_dht_id;
    int byte_idx = b / 8;
    int bit_idx  = 7 - (b % 8);
    rand_id.bytes[byte_idx] ^= (uint8_t)(1 << bit_idx);
    if (byte_idx + 1 < DHT_ID_BYTES &&
        !crypto_random_bytes(rand_id.bytes + byte_idx + 1,
                             (size_t)(DHT_ID_BYTES - byte_idx - 1)))
        dht_log("RNG not available for dht refresh; using fallback");
    dht_log("refresh bucket %d", b);
    int slot = dht_lookup_alloc(rand_id, false);
    if (slot >= 0) dht_lookup_start(slot);
}

void dht_refresh_buckets(void)
{
    time_t now = time(NULL);
    for (int b = 0; b < DHT_BUCKETS; b++) {
        kbucket_t *kb = &dht_routing_table[b];
        if (kb->count == 0) continue;
        if (now - kb->last_changed > DHT_BUCKET_REFRESH_INTERVAL)
            dht_refresh_bucket(b);
    }
}

void dht_republish_keys(void)
{
    time_t now = time(NULL);
    int republished = 0;

    for (int i = 0; i < DHT_STORE_MAX; i++) {
        if (!dht_store[i].used) continue;
        if (dht_store[i].expire < now) { dht_store[i].used = false; continue; }
        if (now - dht_store[i].stored_at < DHT_REPUBLISH_INTERVAL) continue;

        dht_node_t closest[DHT_K];
        int count = 0;
        dht_find_node_local(dht_store[i].key, closest, &count);

        size_t max_plen = DHT_ID_BYTES + 4 + 2 + dht_store[i].value_len;
        uint8_t *payload = malloc(max_plen);
        if (payload) {
            dht_msgbuf_t msg;
            dht_msgbuf_init(&msg, payload, max_plen);
            dht_msgbuf_append(&msg, dht_store[i].key.bytes, DHT_ID_BYTES);
            dht_msgbuf_append_u32(&msg, DHT_TTL);
            dht_msgbuf_append_u16(&msg, (uint16_t)dht_store[i].value_len);
            dht_msgbuf_append(&msg, dht_store[i].value, dht_store[i].value_len);
            
            for (int j = 0; j < count; j++)
                dht_send(closest[j].net_id, M_DHT_STORE, 
                         dht_msgbuf_data(&msg), dht_msgbuf_size(&msg));
            free(payload);
            republished++;
        }
        dht_store[i].stored_at = now;
    }
    if (republished > 0)
        dht_log("republish: %d keys resent", republished);
    last_republish_time = now;
}

static size_t dht_serialize_nodes(const dht_node_t *nodes, int count,
                                   uint8_t *out, size_t out_max)
{
    dht_msgbuf_t msg;
    dht_msgbuf_init(&msg, out, out_max);
    
    for (int i = 0; i < count; i++) {
        // Check if we have space for one more node (26 bytes)
        if (msg.size + 26 > msg.capacity) break;
        
        dht_msgbuf_append(&msg, nodes[i].dht_id.bytes, DHT_ID_BYTES);
        dht_msgbuf_append(&msg, nodes[i].net_id.id, 6);
    }
    
    return dht_msgbuf_size(&msg);
}

static int dht_deserialize_nodes(const uint8_t *buf, size_t len,
                                  dht_node_t *out, int max_out)
{
    dht_msgread_t r;
    dht_msgread_init(&r, buf, len);
    
    int count = 0;
    while (dht_msgread_remaining(&r) >= 26 && count < max_out) {
        dht_msgread_bytes(&r, out[count].dht_id.bytes, DHT_ID_BYTES);
        dht_msgread_bytes(&r, out[count].net_id.id, 6);
        count++;
    }
    
    return count;
}

void dht_init(void)
{
    memset(dht_routing_table, 0, sizeof(dht_routing_table));
    memset(dht_store,         0, sizeof(dht_store));
    memset(dht_lookups,       0, sizeof(dht_lookups));
    memset(&dht_stats,        0, sizeof(dht_stats));
    memset(dht_pending_cbs,   0, sizeof(dht_pending_cbs));
    dht_init_my_id();
}

void dht_bootstrap(node_id_t seed)
{
    dht_node_t dn;
    if (!dht_endpoint_is_valid(seed)) {
        dht_log("bootstrap: non-public endpoint rejected %s", id2str(seed));
        return;
    }
    dn.net_id = seed;
    /* temp ID until handshake reveals the peer's ephemeral pubkey */
    dn.dht_id = dht_id_from_net(seed);
    dht_routing_table_add(dn);
    dht_bootstrap_pending = true;
}

void dht_put(const char *key_str, const uint8_t *value, size_t vlen)
{
    if (vlen > DHT_VALUE_MAX) {
        dht_log("PUT: value truncated from %zu to %d bytes", vlen, DHT_VALUE_MAX);
        vlen = DHT_VALUE_MAX;
    }

    dht_id_t key;
    dht_hash_id((const uint8_t *)key_str, strlen(key_str), key.bytes);
    dht_log("PUT key=%s vlen=%zu", dht_id2str(key), vlen);
    dht_store_local(key, value, vlen, DHT_TTL);

    dht_node_t closest[DHT_K];
    int count = 0;
    dht_find_node_local(key, closest, &count);
    if (count == 0) { dht_log("PUT: no nodes, stored locally only"); return; }

    size_t max_plen = DHT_ID_BYTES + 4 + 2 + vlen;
    uint8_t *payload = malloc(max_plen);
    if (!payload) return;
    
    dht_msgbuf_t msg;
    dht_msgbuf_init(&msg, payload, max_plen);
    dht_msgbuf_append(&msg, key.bytes, DHT_ID_BYTES);
    dht_msgbuf_append_u32(&msg, DHT_TTL);
    dht_msgbuf_append_u16(&msg, (uint16_t)vlen);
    dht_msgbuf_append(&msg, value, vlen);
    
    for (int i = 0; i < count; i++)
        dht_send(closest[i].net_id, M_DHT_STORE, 
                 dht_msgbuf_data(&msg), dht_msgbuf_size(&msg));
    free(payload);
}

/* MODIFIED: accepts optional callback and registers it */
bool dht_get_async(const char *key_str, uint8_t *out, size_t *out_len)
{
    dht_id_t key;
    dht_hash_id((const uint8_t *)key_str, strlen(key_str), key.bytes);
    dht_log("GET key=%s", dht_id2str(key));
    if (dht_lookup_local(key, out, out_len)) {
        dht_log("GET: found locally");
        dht_stats.successful_lookups++;
        return true;
    }
    int slot = dht_lookup_alloc(key, true);
    if (slot < 0) { dht_log("GET: no lookup slots available"); return false; }
    dht_lookup_start(slot);
    dht_log("GET: lookup %u started", dht_lookups[slot].lookup_id);
    return false;
}

/* new variant with callback — doesn't break original dht_get_async signature */
bool dht_get_async_cb(const char *key_str, uint8_t *out, size_t *out_len,
                      dht_get_cb_t cb, void *userdata)
{
    dht_id_t key;
    dht_hash_id((const uint8_t *)key_str, strlen(key_str), key.bytes);
    dht_log("GET_CB key=%s", dht_id2str(key));
    if (dht_lookup_local(key, out, out_len)) {
        dht_log("GET_CB: found locally");
        dht_stats.successful_lookups++;
        if (cb) cb(key_str, out, *out_len, userdata);
        return true;
    }
    int slot = dht_lookup_alloc(key, true);
    if (slot < 0) { dht_log("GET_CB: no lookup slots available"); return false; }
    dht_cb_register(slot, key_str, cb, userdata);
    dht_lookup_start(slot);
    dht_log("GET_CB: lookup %u started", dht_lookups[slot].lookup_id);
    return false;
}

void dht_shutdown(void)
{
    for (int i = 0; i < DHT_LOOKUP_MAX; i++)
        if (dht_lookups[i].active) dht_lookup_finish(i);
    dht_log("shutdown. lookups=%llu ok=%llu stores=%llu",
            (unsigned long long)dht_stats.total_lookups,
            (unsigned long long)dht_stats.successful_lookups,
            (unsigned long long)dht_stats.total_stores);
}

void handle_dht_packet(node_id_t src, uint8_t msg_type,
                               uint8_t *data, size_t data_len)
{
    dht_node_t sender;
    sender.net_id = src;
    sender.dht_id = dht_id_from_net(src);
    dht_routing_table_add(sender);

    switch (msg_type) {
    case M_DHT_PING:
        dht_stats.total_pings_recv++;
        dht_send(src, M_DHT_PONG, my_dht_id.bytes, DHT_ID_BYTES);
        dht_stats.total_pings_sent++;
        break;

    case M_DHT_PONG:
        if (data_len >= DHT_ID_BYTES) {
            dht_id_t rid;
            memcpy(rid.bytes, data, DHT_ID_BYTES);
            sender.dht_id = rid;
            dht_routing_table_add(sender);
            dht_bucket_on_pong(rid);
            dht_node_record_success(rid);
        }
        break;

    case M_DHT_FIND_NODE: {
        uint32_t lid = 0;
        dht_id_t target;
        if (data_len >= 24) {
            memcpy(&lid, data, 4); lid = ntohl(lid);
            memcpy(target.bytes, data+4, DHT_ID_BYTES);
        } else if (data_len >= DHT_ID_BYTES) {
            memcpy(target.bytes, data, DHT_ID_BYTES);
        } else break;

        dht_node_t closest[DHT_K]; int count = 0;
        dht_find_node_local(target, closest, &count);
        size_t rlen = 4 + (size_t)count * 26;
        uint8_t *resp = malloc(rlen);
        if (!resp) break;
        uint32_t lid_net = htonl(lid);
        memcpy(resp, &lid_net, 4);
        dht_serialize_nodes(closest, count, resp+4, rlen-4);
        dht_send(src, M_DHT_FOUND_NODE, resp, rlen);
        free(resp);
        break;
    }

    case M_DHT_FOUND_NODE: {
        if (data_len < 4) break;
        uint32_t lid; memcpy(&lid, data, 4); lid = ntohl(lid);
        int count = (int)((data_len-4) / 26);
        if (count <= 0) break;
        dht_node_t nodes[DHT_SHORTLIST_MAX];
        int n = dht_deserialize_nodes(data+4, data_len-4, nodes,
                                       count < DHT_SHORTLIST_MAX ? count
                                                                  : DHT_SHORTLIST_MAX);
        for (int i = 0; i < n; i++) dht_routing_table_add(nodes[i]);
        dht_lookup_on_found_nodes(lid, src, nodes, n);
        break;
    }

    case M_DHT_FIND_VALUE: {
        uint32_t lid = 0; dht_id_t key;
        if (data_len >= 24) {
            memcpy(&lid, data, 4); lid = ntohl(lid);
            memcpy(key.bytes, data+4, DHT_ID_BYTES);
        } else if (data_len >= DHT_ID_BYTES) {
            memcpy(key.bytes, data, DHT_ID_BYTES);
        } else break;

        uint8_t val[DHT_VALUE_MAX]; size_t vlen = 0;
        if (dht_lookup_local(key, val, &vlen)) {
            size_t plen = 4 + 20 + 2 + vlen;
            uint8_t *resp = malloc(plen);
            if (resp) {
                uint32_t lid_net = htonl(lid);
                uint16_t vlen_net = htons((uint16_t)vlen);
                memcpy(resp, &lid_net, 4);
                memcpy(resp+4, key.bytes, 20);
                memcpy(resp+24, &vlen_net, 2);
                memcpy(resp+26, val, vlen);
                dht_send(src, M_DHT_FOUND_VALUE, resp, plen);
                free(resp);
            }
        } else {
            dht_node_t closest[DHT_K]; int count = 0;
            dht_find_node_local(key, closest, &count);
            size_t rlen = 4 + (size_t)count * 26;
            uint8_t *resp = malloc(rlen);
            if (resp) {
                uint32_t lid_net = htonl(lid);
                memcpy(resp, &lid_net, 4);
                dht_serialize_nodes(closest, count, resp+4, rlen-4);
                dht_send(src, M_DHT_FOUND_NODE, resp, rlen);
                free(resp);
            }
        }
        break;
    }

    case M_DHT_FOUND_VALUE: {
        if (data_len < 26) break;
        uint32_t lid; memcpy(&lid, data, 4); lid = ntohl(lid);
        dht_id_t key; memcpy(key.bytes, data+4, 20);
        uint16_t vlen_net; memcpy(&vlen_net, data+24, 2);
        size_t vlen = ntohs(vlen_net);
        if (26 + vlen > data_len) break;
        dht_lookup_on_found_value(lid, key, data+26, vlen);
        break;
    }

    case M_DHT_STORE: {
        if (data_len < 26) break;
        const char *guard_reason = NULL;
        if (!p2p_guard_allow_dht_store(src, &guard_reason)) {
            dht_log("GUARD STORE from %s rejected: %s",
                    id2str(src), guard_reason ? guard_reason : "policy");
            break;
        }
        if (!dht_rate_check_store(src)) break;
        dht_id_t key; memcpy(key.bytes, data, 20);
        uint32_t ttl_net; memcpy(&ttl_net, data+20, 4);
        uint32_t ttl = ntohl(ttl_net);
        uint16_t vlen_net; memcpy(&vlen_net, data+24, 2);
        size_t vlen = ntohs(vlen_net);
        if (vlen > DHT_VALUE_MAX || 26 + vlen > data_len) break;
        if (ttl == 0 || ttl > (uint32_t)DHT_TTL * 2) ttl = DHT_TTL;
        dht_store_local(key, data+26, vlen, ttl);
        dht_send(src, M_DHT_STORE_ACK, key.bytes, DHT_ID_BYTES);
        break;
    }

    case M_DHT_STORE_ACK:
        dht_node_record_success(sender.dht_id);
        break;

    default:
        dht_log("unknown DHT message type=%d from %s", msg_type, id2str(src));
        break;
    }
}
