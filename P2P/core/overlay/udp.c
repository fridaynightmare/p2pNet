// udp.c - bounded reliable UDP transport for the P2P overlay

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "udp_transport.h"

#define UDP_MAGIC_LEN             4
#define UDP_HEADER_SIZE          16
#define UDP_MAX_CONNECTIONS     256
#define UDP_MAX_PAYLOAD        1300
#define UDP_RECV_BUFFER        2048
#define UDP_SEND_WINDOW          64
#define UDP_REORDER_WINDOW       32
#define UDP_INITIAL_RTO_MS      500
#define UDP_MAX_RTO_MS        30000
#define UDP_MAX_RETRIES           8
#define UDP_CONNECT_TIMEOUT_MS 45000
#define UDP_IDLE_TIMEOUT_MS   180000
#define UDP_KEEPALIVE_MS       30000

enum udp_msg_type {
    UDP_MSG_HELLO = 1,
    UDP_MSG_HELLO_ACK,
    UDP_MSG_ACK,
    UDP_MSG_DATA,
    UDP_MSG_BYE,
    UDP_MSG_PING
};

enum udp_conn_state {
    UDP_CONN_CLOSED = 0,
    UDP_CONN_CONNECTING,
    UDP_CONN_CONNECTED
};

typedef struct __attribute__((packed)) {
    uint8_t magic[UDP_MAGIC_LEN];
    uint32_t seq;
    uint32_t ack;
    uint8_t type;
    uint8_t flags;
    uint16_t payload_len;
} udp_wire_header_t;

_Static_assert(sizeof(udp_wire_header_t) == UDP_HEADER_SIZE,
               "unexpected UDP wire header size");

typedef struct {
    bool used;
    uint32_t seq;
    size_t len;
    uint8_t data[UDP_MAX_PAYLOAD];
    uint64_t last_sent_ms;
    uint32_t rto_ms;
    unsigned retries;
} udp_send_slot_t;

typedef struct {
    bool used;
    uint32_t seq;
    size_t len;
    uint8_t data[UDP_MAX_PAYLOAD];
} udp_reorder_slot_t;

typedef struct {
    int id;
    enum udp_conn_state state;
    struct sockaddr_in peer;
    uint32_t hello_seq;
    uint32_t send_next;
    uint32_t recv_next;
    uint64_t created_ms;
    uint64_t last_activity_ms;
    uint64_t last_keepalive_ms;
    uint64_t hello_sent_ms;
    uint32_t hello_rto_ms;
    unsigned hello_retries;
    udp_send_slot_t sendq[UDP_SEND_WINDOW];
    udp_reorder_slot_t reorder[UDP_REORDER_WINDOW];
    udp_on_connect_cb_t on_connect;
    udp_on_data_cb_t on_data;
    udp_on_close_cb_t on_close;
    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t retransmits;
} udp_connection_t;

enum udp_event_type {
    UDP_EVENT_CONNECT,
    UDP_EVENT_DATA,
    UDP_EVENT_CLOSE
};

typedef struct {
    enum udp_event_type type;
    int conn_id;
    udp_on_connect_cb_t on_connect;
    udp_on_data_cb_t on_data;
    udp_on_close_cb_t on_close;
    size_t len;
    uint8_t data[UDP_MAX_PAYLOAD];
} udp_event_t;

static const uint8_t UDP_MAGIC[UDP_MAGIC_LEN] = {'P', '2', 'P', 2};
static int g_socket = -1;
static udp_connection_t g_connections[UDP_MAX_CONNECTIONS];
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static udp_on_connect_cb_t g_default_connect;
static udp_on_data_cb_t g_default_data;
static udp_on_close_cb_t g_default_close;
static char g_last_error[256];

static uint64_t udp_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void udp_set_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_last_error, sizeof(g_last_error), fmt, ap);
    va_end(ap);
}

static uint32_t udp_random_u32(void)
{
    uint32_t value = 0;
    if (!crypto_random_bytes((uint8_t *)&value, sizeof(value)) || value == 0)
        value = (uint32_t)xr64_rand();
    return value ? value : 1;
}

static bool udp_seq_after(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) > 0;
}

static udp_connection_t *udp_find_by_addr_locked(const struct sockaddr_in *peer)
{
    for (int i = 0; i < UDP_MAX_CONNECTIONS; ++i) {
        udp_connection_t *conn = &g_connections[i];
        if (conn->state != UDP_CONN_CLOSED &&
            conn->peer.sin_addr.s_addr == peer->sin_addr.s_addr &&
            conn->peer.sin_port == peer->sin_port)
            return conn;
    }
    return NULL;
}

static udp_connection_t *udp_find_by_id_locked(int conn_id)
{
    if (conn_id < 0 || conn_id >= UDP_MAX_CONNECTIONS)
        return NULL;
    return g_connections[conn_id].state == UDP_CONN_CLOSED
               ? NULL
               : &g_connections[conn_id];
}

static udp_connection_t *udp_alloc_locked(const struct sockaddr_in *peer)
{
    for (int i = 0; i < UDP_MAX_CONNECTIONS; ++i) {
        udp_connection_t *conn = &g_connections[i];
        if (conn->state != UDP_CONN_CLOSED)
            continue;
        memset(conn, 0, sizeof(*conn));
        conn->id = i;
        conn->peer = *peer;
        conn->hello_seq = udp_random_u32();
        conn->send_next = conn->hello_seq + 1;
        conn->created_ms = conn->last_activity_ms = udp_now_ms();
        conn->last_keepalive_ms = conn->created_ms;
        conn->hello_rto_ms = UDP_INITIAL_RTO_MS;
        return conn;
    }
    return NULL;
}

static void udp_release_locked(udp_connection_t *conn)
{
    int id = conn->id;
    memset(conn, 0, sizeof(*conn));
    conn->id = id;
    conn->state = UDP_CONN_CLOSED;
}

static bool udp_send_packet_locked(udp_connection_t *conn, uint8_t type,
                                   uint32_t seq, uint32_t ack,
                                   const uint8_t *payload, size_t payload_len)
{
    if (g_socket < 0 || payload_len > UDP_MAX_PAYLOAD)
        return false;

    uint8_t packet[UDP_HEADER_SIZE + UDP_MAX_PAYLOAD];
    udp_wire_header_t header;
    memcpy(header.magic, UDP_MAGIC, sizeof(header.magic));
    header.seq = htonl(seq);
    header.ack = htonl(ack);
    header.type = type;
    header.flags = 0;
    header.payload_len = htons((uint16_t)payload_len);
    memcpy(packet, &header, sizeof(header));
    if (payload_len)
        memcpy(packet + sizeof(header), payload, payload_len);

    ssize_t sent = sendto(g_socket, packet, sizeof(header) + payload_len, 0,
                          (struct sockaddr *)&conn->peer, sizeof(conn->peer));
    if (sent != (ssize_t)(sizeof(header) + payload_len)) {
        udp_set_error("sendto: %s", strerror(errno));
        return false;
    }
    conn->tx_packets++;
    return true;
}

static void udp_add_connect_event(udp_event_t *events, size_t *count,
                                  udp_connection_t *conn)
{
    udp_event_t *event = &events[(*count)++];
    memset(event, 0, sizeof(*event));
    event->type = UDP_EVENT_CONNECT;
    event->conn_id = conn->id;
    event->on_connect = conn->on_connect;
}

static void udp_add_data_event(udp_event_t *events, size_t *count,
                               udp_connection_t *conn,
                               const uint8_t *data, size_t len)
{
    udp_event_t *event = &events[(*count)++];
    memset(event, 0, sizeof(*event));
    event->type = UDP_EVENT_DATA;
    event->conn_id = conn->id;
    event->on_data = conn->on_data;
    event->len = len;
    memcpy(event->data, data, len);
}

static void udp_add_close_event(udp_event_t *events, size_t *count,
                                udp_connection_t *conn)
{
    udp_event_t *event = &events[(*count)++];
    memset(event, 0, sizeof(*event));
    event->type = UDP_EVENT_CLOSE;
    event->conn_id = conn->id;
    event->on_close = conn->on_close;
}

static void udp_dispatch_events(udp_event_t *events, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        udp_event_t *event = &events[i];
        if (event->type == UDP_EVENT_CONNECT && event->on_connect)
            event->on_connect(event->conn_id);
        else if (event->type == UDP_EVENT_DATA && event->on_data)
            event->on_data(event->conn_id, event->data, event->len);
        else if (event->type == UDP_EVENT_CLOSE && event->on_close)
            event->on_close(event->conn_id);
    }
}

static void udp_ack_sendq_locked(udp_connection_t *conn, uint32_t ack)
{
    for (size_t i = 0; i < UDP_SEND_WINDOW; ++i) {
        udp_send_slot_t *slot = &conn->sendq[i];
        if (slot->used && !udp_seq_after(slot->seq, ack))
            memset(slot, 0, sizeof(*slot));
    }
}

static udp_reorder_slot_t *udp_find_reorder_locked(udp_connection_t *conn,
                                                    uint32_t seq)
{
    for (size_t i = 0; i < UDP_REORDER_WINDOW; ++i)
        if (conn->reorder[i].used && conn->reorder[i].seq == seq)
            return &conn->reorder[i];
    return NULL;
}

static void udp_store_reorder_locked(udp_connection_t *conn, uint32_t seq,
                                     const uint8_t *data, size_t len)
{
    if ((uint32_t)(seq - conn->recv_next) >= UDP_REORDER_WINDOW ||
        udp_find_reorder_locked(conn, seq))
        return;
    for (size_t i = 0; i < UDP_REORDER_WINDOW; ++i) {
        udp_reorder_slot_t *slot = &conn->reorder[i];
        if (!slot->used) {
            slot->used = true;
            slot->seq = seq;
            slot->len = len;
            memcpy(slot->data, data, len);
            return;
        }
    }
}

static void udp_deliver_contiguous_locked(udp_connection_t *conn,
                                          udp_event_t *events, size_t *count,
                                          const uint8_t *data, size_t len)
{
    udp_add_data_event(events, count, conn, data, len);
    conn->recv_next++;
    for (;;) {
        udp_reorder_slot_t *slot = udp_find_reorder_locked(conn, conn->recv_next);
        if (!slot)
            break;
        udp_add_data_event(events, count, conn, slot->data, slot->len);
        memset(slot, 0, sizeof(*slot));
        conn->recv_next++;
    }
}

static void udp_handle_datagram(const uint8_t *packet, size_t packet_len,
                                const struct sockaddr_in *from)
{
    if (packet_len < sizeof(udp_wire_header_t))
        return;

    udp_wire_header_t header;
    memcpy(&header, packet, sizeof(header));
    if (memcmp(header.magic, UDP_MAGIC, sizeof(header.magic)) != 0)
        return;

    uint16_t payload_len = ntohs(header.payload_len);
    if (payload_len > UDP_MAX_PAYLOAD ||
        packet_len != sizeof(header) + payload_len)
        return;

    uint32_t seq = ntohl(header.seq);
    uint32_t ack = ntohl(header.ack);
    const uint8_t *payload = packet + sizeof(header);
    udp_event_t events[UDP_REORDER_WINDOW + 2];
    size_t event_count = 0;

    pthread_mutex_lock(&g_mutex);
    udp_connection_t *conn = udp_find_by_addr_locked(from);

    if (header.type == UDP_MSG_HELLO) {
        if (!conn) {
            conn = udp_alloc_locked(from);
            if (!conn) {
                pthread_mutex_unlock(&g_mutex);
                return;
            }
            conn->on_connect = g_default_connect;
            conn->on_data = g_default_data;
            conn->on_close = g_default_close;
        }
        bool notify = conn->state != UDP_CONN_CONNECTED;
        if (notify) {
            conn->recv_next = seq + 1;
            conn->state = UDP_CONN_CONNECTED;
        }
        conn->last_activity_ms = udp_now_ms();
        conn->rx_packets++;
        (void)udp_send_packet_locked(conn, UDP_MSG_HELLO_ACK,
                                     conn->hello_seq, seq, NULL, 0);
        if (notify)
            udp_add_connect_event(events, &event_count, conn);
    } else if (conn) {
        conn->rx_packets++;
        conn->last_activity_ms = udp_now_ms();
        udp_ack_sendq_locked(conn, ack);

        if (header.type == UDP_MSG_HELLO_ACK &&
            conn->state == UDP_CONN_CONNECTING && ack == conn->hello_seq) {
            conn->recv_next = seq + 1;
            conn->state = UDP_CONN_CONNECTED;
            (void)udp_send_packet_locked(conn, UDP_MSG_ACK, 0, seq, NULL, 0);
            udp_add_connect_event(events, &event_count, conn);
        } else if (header.type == UDP_MSG_DATA &&
                   conn->state == UDP_CONN_CONNECTED) {
            if (seq == conn->recv_next)
                udp_deliver_contiguous_locked(conn, events, &event_count,
                                              payload, payload_len);
            else if (udp_seq_after(seq, conn->recv_next))
                udp_store_reorder_locked(conn, seq, payload, payload_len);
            (void)udp_send_packet_locked(conn, UDP_MSG_ACK, 0,
                                         conn->recv_next - 1, NULL, 0);
        } else if (header.type == UDP_MSG_PING) {
            (void)udp_send_packet_locked(conn, UDP_MSG_ACK, 0,
                                         conn->recv_next - 1, NULL, 0);
        } else if (header.type == UDP_MSG_BYE) {
            udp_add_close_event(events, &event_count, conn);
            udp_release_locked(conn);
        }
    }
    pthread_mutex_unlock(&g_mutex);
    udp_dispatch_events(events, event_count);
}

void udp_transport_set_callbacks(udp_on_connect_cb_t on_connect,
                                 udp_on_data_cb_t on_data,
                                 udp_on_close_cb_t on_close)
{
    pthread_mutex_lock(&g_mutex);
    g_default_connect = on_connect;
    g_default_data = on_data;
    g_default_close = on_close;
    pthread_mutex_unlock(&g_mutex);
}

int udp_transport_init(int local_port)
{
    pthread_mutex_lock(&g_mutex);
    if (g_socket >= 0) {
        pthread_mutex_unlock(&g_mutex);
        return 0;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        udp_set_error("socket: %s", strerror(errno));
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        udp_set_error("fcntl: %s", strerror(errno));
        close(fd);
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons((uint16_t)local_port);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        udp_set_error("bind: %s", strerror(errno));
        close(fd);
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }

    memset(g_connections, 0, sizeof(g_connections));
    for (int i = 0; i < UDP_MAX_CONNECTIONS; ++i)
        g_connections[i].id = i;
    g_socket = fd;
    g_last_error[0] = '\0';
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

void udp_transport_shutdown(void)
{
    pthread_mutex_lock(&g_mutex);
    if (g_socket >= 0)
        close(g_socket);
    g_socket = -1;
    memset(g_connections, 0, sizeof(g_connections));
    pthread_mutex_unlock(&g_mutex);
}

int udp_transport_connect(const struct sockaddr_in *peer_addr,
                          udp_on_connect_cb_t on_connect,
                          udp_on_data_cb_t on_data,
                          udp_on_close_cb_t on_close)
{
    if (!peer_addr || peer_addr->sin_family != AF_INET) {
        udp_set_error("invalid peer address");
        return -1;
    }

    pthread_mutex_lock(&g_mutex);
    if (g_socket < 0) {
        udp_set_error("transport is not initialized");
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }
    udp_connection_t *existing = udp_find_by_addr_locked(peer_addr);
    if (existing) {
        int id = existing->id;
        pthread_mutex_unlock(&g_mutex);
        return id;
    }

    udp_connection_t *conn = udp_alloc_locked(peer_addr);
    if (!conn) {
        udp_set_error("connection table is full");
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }
    conn->state = UDP_CONN_CONNECTING;
    conn->on_connect = on_connect ? on_connect : g_default_connect;
    conn->on_data = on_data ? on_data : g_default_data;
    conn->on_close = on_close ? on_close : g_default_close;
    if (!udp_send_packet_locked(conn, UDP_MSG_HELLO,
                                conn->hello_seq, 0, NULL, 0)) {
        udp_release_locked(conn);
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }
    conn->hello_sent_ms = udp_now_ms();
    int id = conn->id;
    pthread_mutex_unlock(&g_mutex);
    return id;
}

ssize_t udp_transport_write(int conn_id, const uint8_t *data, size_t len)
{
    if ((!data && len) || len == 0)
        return len == 0 ? 0 : -1;

    size_t chunks = (len + UDP_MAX_PAYLOAD - 1) / UDP_MAX_PAYLOAD;
    if (chunks > UDP_SEND_WINDOW) {
        udp_set_error("write exceeds send window");
        return -1;
    }

    pthread_mutex_lock(&g_mutex);
    udp_connection_t *conn = udp_find_by_id_locked(conn_id);
    if (!conn || conn->state != UDP_CONN_CONNECTED) {
        udp_set_error("connection is not established");
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }

    size_t free_slots = 0;
    for (size_t i = 0; i < UDP_SEND_WINDOW; ++i)
        if (!conn->sendq[i].used)
            free_slots++;
    if (free_slots < chunks) {
        udp_set_error("send window is full");
        pthread_mutex_unlock(&g_mutex);
        return -1;
    }

    size_t offset = 0;
    uint64_t now = udp_now_ms();
    for (size_t i = 0; i < UDP_SEND_WINDOW && offset < len; ++i) {
        udp_send_slot_t *slot = &conn->sendq[i];
        if (slot->used)
            continue;
        slot->used = true;
        slot->seq = conn->send_next++;
        slot->len = len - offset > UDP_MAX_PAYLOAD ? UDP_MAX_PAYLOAD : len - offset;
        memcpy(slot->data, data + offset, slot->len);
        slot->rto_ms = UDP_INITIAL_RTO_MS;
        slot->last_sent_ms = now;
        /* Once admitted to the send window the whole write is accepted.
         * A transient sendto failure is recovered by the retransmit timer. */
        (void)udp_send_packet_locked(conn, UDP_MSG_DATA, slot->seq,
                                     conn->recv_next - 1,
                                     slot->data, slot->len);
        offset += slot->len;
    }
    conn->last_activity_ms = now;
    pthread_mutex_unlock(&g_mutex);
    return (ssize_t)len;
}

void udp_transport_close(int conn_id)
{
    pthread_mutex_lock(&g_mutex);
    udp_connection_t *conn = udp_find_by_id_locked(conn_id);
    if (conn) {
        (void)udp_send_packet_locked(conn, UDP_MSG_BYE, 0,
                                     conn->recv_next - 1, NULL, 0);
        /* A local close is already known to the overlay.  Do not invoke the
         * callback while its lock may be held. */
        udp_release_locked(conn);
    }
    pthread_mutex_unlock(&g_mutex);
}

void udp_transport_tick(void)
{
    if (g_socket < 0)
        return;

    for (;;) {
        uint8_t packet[UDP_RECV_BUFFER];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t len = recvfrom(g_socket, packet, sizeof(packet), 0,
                               (struct sockaddr *)&from, &from_len);
        if (len < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                udp_set_error("recvfrom: %s", strerror(errno));
            break;
        }
        udp_handle_datagram(packet, (size_t)len, &from);
    }

    udp_event_t close_events[UDP_MAX_CONNECTIONS];
    size_t close_count = 0;
    uint64_t now = udp_now_ms();
    pthread_mutex_lock(&g_mutex);
    for (int i = 0; i < UDP_MAX_CONNECTIONS; ++i) {
        udp_connection_t *conn = &g_connections[i];
        if (conn->state == UDP_CONN_CLOSED)
            continue;

        bool close_conn = false;
        if (conn->state == UDP_CONN_CONNECTING) {
            if (now - conn->created_ms >= UDP_CONNECT_TIMEOUT_MS ||
                conn->hello_retries >= UDP_MAX_RETRIES) {
                close_conn = true;
            } else if (now - conn->hello_sent_ms >= conn->hello_rto_ms) {
                (void)udp_send_packet_locked(conn, UDP_MSG_HELLO,
                                             conn->hello_seq, 0, NULL, 0);
                conn->hello_sent_ms = now;
                conn->hello_retries++;
                conn->hello_rto_ms = conn->hello_rto_ms >= UDP_MAX_RTO_MS / 2
                                         ? UDP_MAX_RTO_MS
                                         : conn->hello_rto_ms * 2;
                conn->retransmits++;
            }
        } else {
            for (size_t j = 0; j < UDP_SEND_WINDOW; ++j) {
                udp_send_slot_t *slot = &conn->sendq[j];
                if (!slot->used || now - slot->last_sent_ms < slot->rto_ms)
                    continue;
                if (slot->retries >= UDP_MAX_RETRIES) {
                    close_conn = true;
                    break;
                }
                (void)udp_send_packet_locked(conn, UDP_MSG_DATA, slot->seq,
                                             conn->recv_next - 1,
                                             slot->data, slot->len);
                slot->last_sent_ms = now;
                slot->retries++;
                slot->rto_ms = slot->rto_ms >= UDP_MAX_RTO_MS / 2
                                   ? UDP_MAX_RTO_MS
                                   : slot->rto_ms * 2;
                conn->retransmits++;
            }
            if (now - conn->last_activity_ms >= UDP_IDLE_TIMEOUT_MS)
                close_conn = true;
            else if (now - conn->last_keepalive_ms >= UDP_KEEPALIVE_MS) {
                (void)udp_send_packet_locked(conn, UDP_MSG_PING, 0,
                                             conn->recv_next - 1, NULL, 0);
                conn->last_keepalive_ms = now;
            }
        }

        if (close_conn) {
            udp_add_close_event(close_events, &close_count, conn);
            udp_release_locked(conn);
        }
    }
    pthread_mutex_unlock(&g_mutex);
    udp_dispatch_events(close_events, close_count);
}

const char *udp_transport_last_error(void)
{
    return g_last_error;
}

int udp_transport_get_peer_addr(int conn_id, struct sockaddr_in *out)
{
    if (!out)
        return -1;
    pthread_mutex_lock(&g_mutex);
    udp_connection_t *conn = udp_find_by_id_locked(conn_id);
    bool found = conn != NULL;
    if (found)
        *out = conn->peer;
    pthread_mutex_unlock(&g_mutex);
    return found ? 0 : -1;
}

void udp_transport_describe_connection(int conn_id, char *buf, size_t buf_size)
{
    if (!buf || !buf_size)
        return;
    pthread_mutex_lock(&g_mutex);
    udp_connection_t *conn = udp_find_by_id_locked(conn_id);
    if (!conn) {
        snprintf(buf, buf_size, "closed");
    } else {
        char addr[INET_ADDRSTRLEN] = "?";
        (void)inet_ntop(AF_INET, &conn->peer.sin_addr, addr, sizeof(addr));
        snprintf(buf, buf_size, "%s:%u state=%d tx=%llu rx=%llu rtx=%llu",
                 addr, ntohs(conn->peer.sin_port), conn->state,
                 (unsigned long long)conn->tx_packets,
                 (unsigned long long)conn->rx_packets,
                 (unsigned long long)conn->retransmits);
    }
    pthread_mutex_unlock(&g_mutex);
}

void udp_transport_dump_stats(void)
{
    pthread_mutex_lock(&g_mutex);
    for (int i = 0; i < UDP_MAX_CONNECTIONS; ++i) {
        udp_connection_t *conn = &g_connections[i];
        if (conn->state == UDP_CONN_CLOSED)
            continue;
        char addr[INET_ADDRSTRLEN] = "?";
        (void)inet_ntop(AF_INET, &conn->peer.sin_addr, addr, sizeof(addr));
        net_log("UDP %d %s:%u state=%d tx=%llu rx=%llu retransmits=%llu",
                conn->id, addr, ntohs(conn->peer.sin_port), conn->state,
                (unsigned long long)conn->tx_packets,
                (unsigned long long)conn->rx_packets,
                (unsigned long long)conn->retransmits);
    }
    pthread_mutex_unlock(&g_mutex);
}
