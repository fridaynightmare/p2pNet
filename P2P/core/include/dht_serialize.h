#ifndef DHT_SERIALIZE_H
#define DHT_SERIALIZE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * DHT Serialization Helpers
 * 
 * Safe wrappers for building DHT messages without manual offsets.
 * Uses bytebuf-style API but optimized for DHT use case.
 */

typedef struct {
    uint8_t *data;
    size_t   size;
    size_t   capacity;
} dht_msgbuf_t;

// Initialize a message buffer (stack or heap)
static inline void dht_msgbuf_init(dht_msgbuf_t *buf, uint8_t *storage, size_t cap) {
    buf->data = storage;
    buf->size = 0;
    buf->capacity = cap;
}

// Append raw bytes
static inline bool dht_msgbuf_append(dht_msgbuf_t *buf, const void *data, size_t len) {
    if (buf->size + len > buf->capacity) return false;
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
    return true;
}

// Append uint32_t (network byte order)
static inline bool dht_msgbuf_append_u32(dht_msgbuf_t *buf, uint32_t val) {
    uint32_t net = htonl(val);
    return dht_msgbuf_append(buf, &net, sizeof(net));
}

// Append uint16_t (network byte order)
static inline bool dht_msgbuf_append_u16(dht_msgbuf_t *buf, uint16_t val) {
    uint16_t net = htons(val);
    return dht_msgbuf_append(buf, &net, sizeof(net));
}

// Append uint8_t
static inline bool dht_msgbuf_append_u8(dht_msgbuf_t *buf, uint8_t val) {
    return dht_msgbuf_append(buf, &val, 1);
}

// Get buffer data pointer
static inline const uint8_t *dht_msgbuf_data(const dht_msgbuf_t *buf) {
    return buf->data;
}

// Get buffer size
static inline size_t dht_msgbuf_size(const dht_msgbuf_t *buf) {
    return buf->size;
}

// Reader for parsing DHT messages
typedef struct {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
} dht_msgread_t;

// Initialize reader
static inline void dht_msgread_init(dht_msgread_t *r, const uint8_t *data, size_t len) {
    r->data = data;
    r->size = len;
    r->pos = 0;
}

// Check remaining bytes
static inline size_t dht_msgread_remaining(const dht_msgread_t *r) {
    return (r->pos < r->size) ? (r->size - r->pos) : 0;
}

// Read raw bytes
static inline bool dht_msgread_bytes(dht_msgread_t *r, void *out, size_t len) {
    if (r->pos + len > r->size) return false;
    if (out) memcpy(out, r->data + r->pos, len);
    r->pos += len;
    return true;
}

// Read uint32_t (network byte order)
static inline bool dht_msgread_u32(dht_msgread_t *r, uint32_t *out) {
    uint32_t net;
    if (!dht_msgread_bytes(r, &net, sizeof(net))) return false;
    if (out) *out = ntohl(net);
    return true;
}

// Read uint16_t (network byte order)
static inline bool dht_msgread_u16(dht_msgread_t *r, uint16_t *out) {
    uint16_t net;
    if (!dht_msgread_bytes(r, &net, sizeof(net))) return false;
    if (out) *out = ntohs(net);
    return true;
}

// Read uint8_t
static inline bool dht_msgread_u8(dht_msgread_t *r, uint8_t *out) {
    return dht_msgread_bytes(r, out, 1);
}

// Skip bytes
static inline bool dht_msgread_skip(dht_msgread_t *r, size_t len) {
    return dht_msgread_bytes(r, NULL, len);
}

#endif // DHT_SERIALIZE_H
