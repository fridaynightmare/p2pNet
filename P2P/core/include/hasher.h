#ifndef HASHER_H
#define HASHER_H

#include <stddef.h>
#include <stdint.h>

static inline uint64_t hash_mix(uint64_t h) {
  h ^= h >> 17;
  h *= 0x9e3779b185ebca87ULL;
  h ^= h << 31;
  h *= 0xc4ceb9fe1a85ec53ULL;
  h ^= h >> 29;
  return h;
}

static inline uint64_t hash64(const void *buf, size_t len, uint64_t seed) {
  const uint8_t *bytes = (const uint8_t *)buf;

  uint64_t state = seed ^ 0x811C9DC5;
  size_t blocks = len >> 2;
  size_t remainder = len & 3;

  for (size_t i = 0; i < blocks; i++) {
    uint64_t chunk = 0;

    chunk |= (uint64_t)bytes[i * 4] << 0;
    chunk |= (uint64_t)bytes[i * 4 + 1] << 8;
    chunk |= (uint64_t)bytes[i * 4 + 2] << 16;
    chunk |= (uint64_t)bytes[i * 4 + 3] << 24;

    state ^= chunk;
    state += (state << 5) | (state >> 27);
    state ^= (state >> 11);
    state *= 0x9E3779B1;

    state = hash_mix(state);
  }

  uint64_t last = 0;
  switch (remainder) {
    case 3:
      last |= (uint64_t)bytes[blocks * 4 + 2] << 16;
    case 2:
      last |= (uint64_t)bytes[blocks * 4 + 1] << 8;
    case 1:
      last |= (uint64_t)bytes[blocks * 4] << 0;
      state ^= last;
      state += (state << 3) | (state >> 29);
      state ^= (state >> 13);
      
      state = hash_mix(state);
  }

  state ^= len;
  state ^= (state >> 15);
  state *= 0x85EBCA6B;
  state ^= (state >> 13);
  state *= 0xC2B2AE35;
  state ^= (state >> 16);

  return hash_mix(state);
}

static inline uint32_t hash32(const void *buf, size_t len, uint32_t seed) {
  uint64_t h = hash64(buf, len, seed);
  return h - (h >> 32);
}

#endif
