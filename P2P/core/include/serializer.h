#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// Logging compatible con P2P
#ifndef PRINTF
#define PRINTF(...) fprintf(stderr, __VA_ARGS__)
#endif

typedef struct {
  uint8_t *buffer;
  uint8_t *original;
  size_t size;
} bytebuf_t, *pbytebuf_t;

static inline pbytebuf_t bytebuf_new_read(uint8_t *buffer, size_t size) {
  if (size == 0) return NULL;

  pbytebuf_t buf = malloc(sizeof(bytebuf_t));
  if (!buf) {
    PRINTF("Failed to allocate new byte buffer\n");
    return NULL;
  }

  buf->original = buf->buffer = NULL;
  buf->size = size;

  /* create new buffer to copy */
  if ((buf->original = malloc(size)) == NULL) {
    PRINTF("Failed to allocate buffer of %zu bytes\n", size);
    free(buf);
    return NULL;
  }

  // copy buffer
  memcpy(buf->original, buffer, size);
  buf->buffer = buf->original;

  return buf;
}

static inline pbytebuf_t bytebuf_new_write(void) {
  pbytebuf_t buf = malloc(sizeof(bytebuf_t));
  if (!buf) {
    return NULL;
  }

  buf->original = buf->buffer = NULL;
  buf->size = 0;

  return buf;
}

static inline void bytebuf_free(pbytebuf_t buf, uint8_t *orig) {
  // clear original buffer if exists and not NULL
  free(orig);

  // clear dynamically allocated buffers
  free(buf->original);

  // clear the bytebuf
  free(buf);
}

static inline size_t bytebuf_remaining(pbytebuf_t buf) { return buf ? buf->size : 0; }

static inline void bytebuf_write_uint8(pbytebuf_t buf, uint8_t data) {
  buf->buffer = realloc(buf->buffer, buf->size + sizeof(uint8_t));
  if (buf->buffer == NULL) {
    return;
  }

  buf->buffer[buf->size] = data;
  buf->size += sizeof(uint8_t);
}

static inline void bytebuf_write_uint16(pbytebuf_t buf, uint16_t data) {
  buf->buffer = realloc(buf->buffer, buf->size + sizeof(uint16_t));
  if (buf->buffer == NULL) {
    return;
  }

  uint8_t *buffer = buf->buffer + buf->size;
  buffer[0] = (data >> 8) & 0xFF;
  buffer[1] = data & 0xFF;

  buf->size += sizeof(uint16_t);
}

static inline void bytebuf_write_uint32(pbytebuf_t buf, uint32_t data) {
  buf->buffer = realloc(buf->buffer, buf->size + sizeof(uint32_t));
  if (buf->buffer == NULL) {
    return;
  }

  uint8_t *buffer = buf->buffer + buf->size;
  buffer[0] = (data >> 24) & 0xFF;
  buffer[1] = (data >> 16) & 0xFF;
  buffer[2] = (data >> 8) & 0xFF;
  buffer[3] = data & 0xFF;

  buf->size += sizeof(uint32_t);
}

static inline void bytebuf_write_uint64(pbytebuf_t buf, uint64_t data) {
  buf->buffer = realloc(buf->buffer, buf->size + sizeof(uint64_t));
  if (buf->buffer == NULL) {
    return;
  }

  uint8_t *buffer = buf->buffer + buf->size;
  buffer[0] = (data >> 56) & 0xFF;
  buffer[1] = (data >> 48) & 0xFF;
  buffer[2] = (data >> 40) & 0xFF;
  buffer[3] = (data >> 32) & 0xFF;
  buffer[4] = (data >> 24) & 0xFF;
  buffer[5] = (data >> 16) & 0xFF;
  buffer[6] = (data >> 8) & 0xFF;
  buffer[7] = data & 0xFF;
  buf->size += sizeof(uint64_t);
}

static inline void bytebuf_write_bytes(pbytebuf_t buf, uint8_t *data, size_t size) {
  // prefix length
  bytebuf_write_uint32(buf, (uint32_t)size);

  if (size <= 0) return;

  // allocate enough mem for bytes
  buf->buffer = realloc(buf->buffer, buf->size + size);
  if (buf->buffer == NULL) return;

  // copy data into buf
  memcpy(buf->buffer + buf->size, data, size);
  buf->size += size;
}

static inline void bytebuf_write(pbytebuf_t buf, uint8_t *data, size_t size) {
  if (size <= 0) return;

  // allocate enough mem for bytes
  buf->buffer = realloc(buf->buffer, buf->size + size);
  if (buf->buffer == NULL) return;

  // copy data into buf
  memcpy(buf->buffer + buf->size, data, size);
  buf->size += size;
}

static inline void bytebuf_write_string(pbytebuf_t buf, const char *data) {
  bytebuf_write_bytes(buf, (uint8_t *)data, strlen(data));
}

static inline uint8_t bytebuf_read_uint8(pbytebuf_t buf) {
  if (buf == NULL || buf->size < sizeof(uint8_t)) {
    return 0;
  }

  uint8_t uint8 = *buf->buffer;
  buf->buffer++;
  buf->size--;

  return uint8;
}

static inline uint16_t bytebuf_read_uint16(pbytebuf_t buf) {
  uint16_t data = 0;

  if (buf == NULL || buf->size < sizeof(uint16_t)) {
    return 0;
  }

  memcpy(&data, buf->buffer, sizeof(uint16_t));
  buf->buffer += sizeof(uint16_t);
  buf->size -= sizeof(uint16_t);

  return ntohs(data);
}

static inline uint32_t bytebuf_read_uint32(pbytebuf_t buf) {
  uint32_t data = 0;

  if (buf == NULL || buf->size < sizeof(uint32_t)) {
    return 0;
  }

  memcpy(&data, buf->buffer, sizeof(uint32_t));
  buf->buffer += sizeof(uint32_t);
  buf->size -= sizeof(uint32_t);

  return ntohl(data);
}

static inline uint8_t *bytebuf_read_bytes(pbytebuf_t buf, size_t *out_size) {
  // check if we can read the length prefix
  if (buf->size < sizeof(uint32_t)) {
    return NULL;
  }

  // read in length prefix
  uint32_t size = bytebuf_read_uint32(buf);
  if (buf->size < size) return NULL;

  // get the buffer
  uint8_t *out = buf->buffer;
  if (!out) return NULL;

  // update buf to consume data
  buf->size -= size;
  buf->buffer += size;

  // set output size
  if (out_size) {
    *out_size = size;
  }

  return out;
}

static inline char *bytebuf_read_string(pbytebuf_t buf, size_t *out_size) {
  return (char *)bytebuf_read_bytes(buf, out_size);
}

// Helper: get pointer to buffer data for direct write operations
static inline uint8_t *bytebuf_get_buffer(pbytebuf_t buf) {
  return buf ? buf->buffer : NULL;
}

// Helper: get current buffer size
static inline size_t bytebuf_get_size(pbytebuf_t buf) {
  return buf ? buf->size : 0;
}

// Helper: reset buffer for reuse (keeps allocation)
static inline void bytebuf_reset(pbytebuf_t buf) {
  if (!buf) return;
  buf->buffer = buf->original;
  buf->size = (buf->original != NULL) ? 0 : buf->size;
}

#endif // SERIALIZER_H
