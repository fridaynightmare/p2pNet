#define _POSIX_C_SOURCE 200809L
#include "common.h"
#include <stdlib.h>



void add_passive(uint8_t *ids, int count)
{
    if (count > 64) count = 64;
    
    for (int i = 0; i < count; i++) {
        uint8_t *cur = ids + i * 6;
        node_id_t candidate;
        memcpy(candidate.id, cur, 6);
        if (is_self_node(candidate)) continue;
        if (!p2p_node_id_is_public(candidate)) {
            net_log("pv rejects non-public %s", id2str(candidate));
            continue;
        }
        bool ip_exists = false;
        uint32_t new_ip;
        memcpy(&new_ip, cur, 4);
        
        for (int j = 0; j < as_count && !ip_exists; j++) {
            uint32_t existing_ip;
            memcpy(&existing_ip, as[j]->id.id, 4);
            if (existing_ip == new_ip) ip_exists = true;
        }
        for (int j = 0; j < ps_count && !ip_exists; j++) {
            uint32_t existing_ip;
            memcpy(&existing_ip, ps[j].id.id, 4);
            if (existing_ip == new_ip) {
                // drop old peer from same ip
                net_log("pv replaces peer at ip %s", id2str(ps[j].id));
                ps[j] = ps[ps_count-1];
                ps_count--;
                break;
            }
        }
        
        if (!ip_exists) {
            if (ps_count >= np) {
                int victim = (int)crypto_random_below((uint32_t)ps_count);
                ps[victim] = ps[ps_count-1];
                ps_count--;
            }
            memcpy(ps[ps_count].id.id, cur, 6);
            net_log("pv learns %s (ps=%d/%d)",
                    id2str(ps[ps_count].id), ps_count + 1, np);
            ps_count++;
        }
    }
}

void remove_passive(node_id_t id)
{
    for (int i = 0; i < ps_count; i++) {
        if (!id_equal(ps[i].id.id, id.id)) continue;
        ps[i] = ps[ps_count-1];
        ps_count--;
        return;
    }
}

static void p2p_try_promote_passive(void)
{
    if (as_count >= n0 || ps_count == 0) return;

    net_log("av %d/%d promoting ps (avail=%d)",
            as_count, n0, ps_count);

    int tries = ps_count < 3 ? ps_count : 3;
    int picked[3];
    int picked_n = 0;
    for (int t = 0; t < tries && as_count < n0 && ps_count > 0; t++) {
        int idx = -1;
        int start = (int)crypto_random_below((uint32_t)ps_count);
        for (int scan = 0; scan < ps_count; scan++) {
            int candidate = (start + scan) % ps_count;
            bool already = false;
            for (int p = 0; p < picked_n; p++) {
                if (picked[p] == candidate) { already = true; break; }
            }
            if (!already) { idx = candidate; break; }
        }
        if (idx < 0) break;
        picked[picked_n++] = idx;
        node_id_t target = ps[idx].id;
        net_log("trying ps %s %d/%d",
                id2str(target), t+1, tries);
        connect_to_reason(target, H_NEIGHBOR_LO, "passive-promo");
    }
}

void active_connect(void)
{
    if (as_count >= na || ps_count == 0) return;
    int needed = na - as_count;
    int tries = ps_count < needed ? ps_count : needed;
    if (tries > 3) tries = 3;
    int picked[3];
    int picked_n = 0;

    for (int t = 0; t < tries && ps_count > 0; t++) {
        int idx = -1;
        int start = (int)crypto_random_below((uint32_t)ps_count);
        for (int scan = 0; scan < ps_count; scan++) {
            int candidate = (start + scan) % ps_count;
            bool already = false;
            for (int p = 0; p < picked_n; p++) {
                if (picked[p] == candidate) { already = true; break; }
            }
            if (!already) { idx = candidate; break; }
        }
        if (idx < 0) break;
        picked[picked_n++] = idx;
        node_id_t target = ps[idx].id;
        if (!p2p_node_id_is_public(target)) {
            net_log("ac discards non-public %s", id2str(target));
            remove_passive(target);
            continue;
        }
        uint8_t hello = (as_count >= n0) ? H_NEIGHBOR_HI : H_JOIN;
        connect_to_reason(target, hello, "active-connect");
    }
    p2p_try_promote_passive();
}

static void reconnect_schedule(node_id_t id);

void del_connection(node_id_t id, int no_disconnect)
{
    del_connection_reason(id, no_disconnect, "connection");
}

/* Internal version that assumes mutex is already held */
static void del_connection_reason_locked(node_id_t id, int no_disconnect, const char *reason)
{
    (void)no_disconnect;
    const char *why = (reason && reason[0]) ? reason : "connection";
    int found = -1;
    for (int i = 0; i < as_count; i++) {
        if (id_equal(as[i]->id.id, id.id)) { found = i; break; }
    }
    if (found == -1) return;

    bool may_reconnect = true;
    time_t now = time(NULL);
    long connected_for = 0;
    long idle_for = 0;
    long peer_uptime = -1;
    char peer_arch[16];

    snprintf(peer_arch, sizeof(peer_arch), "%s", as[found]->peer_arch);
    if (as[found]->connected_since > 0 && now >= as[found]->connected_since)
        connected_for = (long)(now - as[found]->connected_since);
    if (as[found]->last_recv > 0 && now >= as[found]->last_recv)
        idle_for = (long)(now - as[found]->last_recv);
    if (as[found]->peer_start_time > 0 && now >= as[found]->peer_start_time)
        peer_uptime = (long)(now - as[found]->peer_start_time);

    if (epoll_fd >= 0)
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, as[found]->fd, NULL);

    if (as[found]->ssl) {
        p2p_conn_shutdown(as[found]->ssl);
        p2p_conn_free(as[found]->ssl);
    }
    close(as[found]->fd);

    active_node_t *dead = as[found];
    as[found] = as[as_count-1];
    as_count--;
    as[as_count] = NULL;
    free(dead);

    if (peer_uptime >= 0) {
        net_log("node %s deleted reason=%s neighbors=%d conn=%lds idle=%lds up=%lds arch=%s",
                id2str(id), why, as_count, connected_for, idle_for,
                peer_uptime, peer_arch);
    } else {
        net_log("node %s deleted reason=%s neighbors=%d conn=%lds idle=%lds up=? arch=%s",
                id2str(id), why, as_count, connected_for, idle_for,
                peer_arch);
    }

    if (may_reconnect && !is_self_node(id) && p2p_node_id_is_public(id)) {
        add_passive(id.id, 1);
        if (as_count < n0)
            reconnect_schedule(id);
    }

    if (as_count < n0) {
        net_log("weak network, searching in pv...");
        p2p_try_promote_passive();
    }
}

void del_connection_reason(node_id_t id, int no_disconnect, const char *reason)
{
    /* FIXED: Protect del_connection_reason with mutex */
    extern pthread_mutex_t peer_mgmt_mutex;
    pthread_mutex_lock(&peer_mgmt_mutex);
    del_connection_reason_locked(id, no_disconnect, reason);
    pthread_mutex_unlock(&peer_mgmt_mutex);
}

static void reconnect_schedule(node_id_t id)
{
    for (int i = 0; i < reconnect_max; i++) {
        if (!reconnect_table[i].in_use) continue;
        if (!id_equal(reconnect_table[i].id.id, id.id)) continue;
        int exp  = reconnect_table[i].attempts < 6 ? reconnect_table[i].attempts : 6;
        int dely = RECONNECT_BACKOFF_BASE * (1 << exp);
        if (dely > RECONNECT_BACKOFF_MAX_SEC) dely = RECONNECT_BACKOFF_MAX_SEC;
        reconnect_table[i].retry_after = time(NULL) + dely;
        net_log("%s queued next %ds attempt %d",
                id2str(id), dely, reconnect_table[i].attempts);
        return;
    }
    for (int i = 0; i < reconnect_max; i++) {
        if (reconnect_table[i].in_use) continue;
        reconnect_table[i].id          = id;
        reconnect_table[i].attempts    = 0;
        reconnect_table[i].retry_after = time(NULL) + RECONNECT_BACKOFF_BASE;
        reconnect_table[i].in_use      = true;
        reconnect_count++;
        net_log("%s added to queue in %ds",
                id2str(id), RECONNECT_BACKOFF_BASE);
        return;
    }
    net_log("queue full %s to pv", id2str(id));
    add_passive(id.id, 1);
}

void reconnect_tick(void)
{
    time_t now = time(NULL);
    if (now < last_reconnect_tick + RECONNECT_TICK_INTERVAL) return;
    last_reconnect_tick = now;
    if (reconnect_count == 0 && as_count >= n0) return;

    for (int i = 0; i < reconnect_max; i++) {
        if (!reconnect_table[i].in_use) continue;
        if (now < reconnect_table[i].retry_after) continue;

        node_id_t id = reconnect_table[i].id;
        if (!p2p_node_id_is_public(id)) {
            net_log("discarding non-public %s", id2str(id));
            reconnect_table[i].in_use = false;
            if (--reconnect_count < 0) reconnect_count = 0;
            continue;
        }

        bool active = false;
        for (int j = 0; j < as_count; j++)
            if (id_equal(as[j]->id.id, id.id)) { active = true; break; }
        if (active) {
            net_log("%s already active removing from queue", id2str(id));
            reconnect_table[i].in_use = false;
            if (--reconnect_count < 0) reconnect_count = 0;
            continue;
        }

        if (reconnect_table[i].attempts >= RECONNECT_MAX_ATTEMPTS) {
            net_log("discarding %s after %d attempts",
                    id2str(id), reconnect_table[i].attempts);
            reconnect_table[i].in_use = false;
            if (--reconnect_count < 0) reconnect_count = 0;
            continue;
        }

        reconnect_table[i].attempts++;
        int exp  = reconnect_table[i].attempts < 6 ? reconnect_table[i].attempts : 6;
        int dely = RECONNECT_BACKOFF_BASE * (1 << exp);
        if (dely > RECONNECT_BACKOFF_MAX_SEC) dely = RECONNECT_BACKOFF_MAX_SEC;
        reconnect_table[i].retry_after = now + dely;

        net_log("reconnect %s attempt %d/%d next %ds",
                id2str(id), reconnect_table[i].attempts,
                RECONNECT_MAX_ATTEMPTS, dely);
        connect_to_reason(id, H_NEIGHBOR_LO, "reconnect-watch");
    }
}


