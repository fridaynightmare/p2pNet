#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher.h"

#define SEED_LEN 32
#define PUBKEY_LEN 32
#define SECRET_LEN 64

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--seed-hex HEX64]\n"
            "\n"
            "Generate control key compatible with Monocypher.\n"
            "Without --seed-hex uses /dev/urandom.\n",
            prog);
}

static bool hex_value(char c, uint8_t *out)
{
    if (c >= '0' && c <= '9') {
        *out = (uint8_t)(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        *out = (uint8_t)(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        *out = (uint8_t)(c - 'A' + 10);
        return true;
    }
    return false;
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;

    if (!hex || strlen(hex) != out_len * 2) {
        return false;
    }

    for (i = 0; i < out_len; ++i) {
        uint8_t hi;
        uint8_t lo;
        if (!hex_value(hex[i * 2], &hi) || !hex_value(hex[i * 2 + 1], &lo)) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool fill_random(uint8_t *buf, size_t len)
{
    FILE *fp = fopen("/dev/urandom", "rb");
    bool ok;

    if (!fp) {
        fprintf(stderr, "Cannot open /dev/urandom: %s\n", strerror(errno));
        return false;
    }

    ok = fread(buf, 1, len, fp) == len;
    if (!ok) {
        fprintf(stderr, "Cannot read random bytes\n");
    }
    fclose(fp);
    return ok;
}

static void print_hex(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
}

int main(int argc, char **argv)
{
    uint8_t seed[SEED_LEN];
    uint8_t secret[SECRET_LEN];
    uint8_t pubkey[PUBKEY_LEN];
    const char *seed_hex = NULL;

    if (argc == 3 && strcmp(argv[1], "--seed-hex") == 0) {
        seed_hex = argv[2];
    } else if (argc != 1) {
        usage(argv[0]);
        return 1;
    }

    if (seed_hex) {
        if (!hex_to_bytes(seed_hex, seed, sizeof(seed))) {
            fprintf(stderr, "--seed-hex must have 64 valid hex chars\n");
            return 1;
        }
    } else if (!fill_random(seed, sizeof(seed))) {
        return 1;
    }

    crypto_eddsa_key_pair(secret, pubkey, seed);

    printf("SECRET_EXTENDED (128 hex): ");
    print_hex(secret, sizeof(secret));
    printf("\n");

    printf("PUBLIC (64 hex):            ");
    print_hex(pubkey, sizeof(pubkey));
    printf("\n");

    printf("\n");
    printf("Paste this in include/bootstrap_config.h:\n");
    printf("#define P2P_COMPILED_CONTROL_PUBKEY_HEX \"");
    print_hex(pubkey, sizeof(pubkey));
    printf("\"\n");

    crypto_wipe(seed, sizeof(seed));
    crypto_wipe(secret, sizeof(secret));
    crypto_wipe(pubkey, sizeof(pubkey));
    return 0;
}
