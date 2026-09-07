#include "common.h"
#include <sys/random.h>

void xr64_seed(void)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, &xr64_state, sizeof(xr64_state));
        close(fd);
        if (n == (ssize_t)sizeof(xr64_state) && xr64_state != 0) return;
    }
    
    if (getrandom(&xr64_state, sizeof(xr64_state), GRND_NONBLOCK) == sizeof(xr64_state)) {
        return;
    }
    
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    xr64_state = ((uint64_t)ts.tv_sec   << 32) ^ ts.tv_nsec
               ^ ((uint64_t)getpid() << 16)
               ^ ((uint64_t)getppid() << 24)
               ^ (uint64_t)my_listen_port;
    if (xr64_state == 0) xr64_state = 0xDEADBEEFCAFEBABEULL;
    
    xr64_state ^= (uint64_t)my_listen_port << 40;
    for (int i = 0; i < 3; i++) {
        xr64_state ^= xr64_state << 13;
        xr64_state ^= xr64_state >> 7;
        xr64_state ^= xr64_state << 17;
    }
}

uint32_t xr64_rand(void)
{
    xr64_state ^= xr64_state << 13;
    xr64_state ^= xr64_state >> 7;
    xr64_state ^= xr64_state << 17;
    return (uint32_t)(xr64_state ^ (xr64_state >> 32));
}

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define S256_ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define S256_CH(x,y,z)   (((x)&(y))^((~(x))&(z)))
#define S256_MAJ(x,y,z)  (((x)&(y))^((x)&(z))^((y)&(z)))
#define S256_EP0(x)  (S256_ROTR(x,2) ^S256_ROTR(x,13)^S256_ROTR(x,22))
#define S256_EP1(x)  (S256_ROTR(x,6) ^S256_ROTR(x,11)^S256_ROTR(x,25))
#define S256_SIG0(x) (S256_ROTR(x,7) ^S256_ROTR(x,18)^((x)>>3))
#define S256_SIG1(x) (S256_ROTR(x,17)^S256_ROTR(x,19)^((x)>>10))

void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    size_t padded = ((len + 8) / 64 + 1) * 64;
    uint8_t *msg = (uint8_t *)calloc(1, padded);
    if (!msg) { memset(out, 0, 32); return; }
    memcpy(msg, data, len);
    msg[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        msg[padded-1-i] = (uint8_t)(bits >> (i*8));

    for (size_t c = 0; c < padded; c += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)msg[c+i*4  ]<<24)|((uint32_t)msg[c+i*4+1]<<16)|
                   ((uint32_t)msg[c+i*4+2]<< 8)|((uint32_t)msg[c+i*4+3]);
        }
        for (int i = 16; i < 64; i++)
            w[i] = S256_SIG1(w[i-2])+w[i-7]+S256_SIG0(w[i-15])+w[i-16];

        uint32_t a=h[0],b=h[1],c2=h[2],d=h[3],
                 e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1=hh+S256_EP1(e)+S256_CH(e,f,g)+sha256_k[i]+w[i];
            uint32_t t2=S256_EP0(a)+S256_MAJ(a,b,c2);
            hh=g; g=f; f=e; e=d+t1;
            d=c2; c2=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c2; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g;  h[7]+=hh;
    }
    free(msg);
    for (int i = 0; i < 8; i++) {
        out[i*4  ]=(uint8_t)(h[i]>>24); out[i*4+1]=(uint8_t)(h[i]>>16);
        out[i*4+2]=(uint8_t)(h[i]>> 8); out[i*4+3]=(uint8_t)(h[i]);
    }
}

void sha256_hex(const uint8_t *data, size_t len, char out[65])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t digest[32];
    sha256(data, len, digest);
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[64] = '\0';
}

#undef S256_ROTR
#undef S256_CH
#undef S256_MAJ
#undef S256_EP0
#undef S256_EP1
#undef S256_SIG0
#undef S256_SIG1

static uint8_t iot_group_key[32];
static bool iot_group_key_configured = false;
static uint8_t control_ed25519_secret_key[CRYPTO_SECKEY_LEN];
static bool control_ed25519_secret_key_configured = false;

void p2p_secure_wipe(void *ptr, size_t len)
{
    if (!ptr) return;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0) *p++ = 0;
}

void p2p_harden_secret_memory(void)
{
    struct rlimit core_limit;
    memset(&core_limit, 0, sizeof(core_limit));
    if (setrlimit(RLIMIT_CORE, &core_limit) != 0)
        net_log("could not disable core dumps: %s", strerror(errno));

#if defined(__linux__) && defined(PR_SET_DUMPABLE)
    if (prctl(PR_SET_DUMPABLE, 0) != 0)
        net_log("could not mark process non-dumpable: %s", strerror(errno));
#endif

    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        net_log("mlockall not available/permitted: %s", strerror(errno));
    else
        net_log("memory locked, secrets in ram wont swap");
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_to_bytes_fixed(const char *hex, uint8_t *out, size_t out_len)
{
    if (!hex || !out || strlen(hex) != out_len * 2) return false;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval((unsigned char)hex[i * 2]);
        int lo = hexval((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void bytes_to_hex_fixed(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static bool crypto_create_ephemeral_identity_seed(uint8_t seed[CRYPTO_SEED_LEN])
{
    if (!seed) return false;
    return crypto_random_bytes(seed, CRYPTO_SEED_LEN);
}

bool crypto_random_bytes(uint8_t *out, size_t len)
{
    if (!out) return false;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        size_t off = 0;
        while (off < len) {
            ssize_t n = read(fd, out + off, len - off);
            if (n <= 0) break;
            off += (size_t)n;
        }
        close(fd);
        if (off == len) return true;
    }

    for (size_t i = 0; i < len; i += 4) {
        uint32_t r = xr64_rand();
        size_t n = (len - i) < 4 ? (len - i) : 4;
        memcpy(out + i, &r, n);
    }
    return false;
}

bool crypto_random_u64(uint64_t *out)
{
    if (!out) return false;
    return crypto_random_bytes((uint8_t *)out, sizeof(*out));
}

uint32_t crypto_random_below(uint32_t n)
{
    if (n <= 1) return 0;

    uint32_t limit = UINT32_MAX - (UINT32_MAX % n);
    for (int tries = 0; tries < 8; tries++) {
        uint32_t r = 0;
        if (!crypto_random_bytes((uint8_t *)&r, sizeof(r)))
            break;
        if (r < limit)
            return r % n;
    }

    return xr64_rand() % n;
}

void crypto_get_group_key_hex(char out[65])
{
    bytes_to_hex_fixed(iot_group_key, sizeof(iot_group_key), out);
}

bool crypto_group_key_is_configured(void)
{
    return iot_group_key_configured;
}

bool crypto_set_group_key_hex(const char *hex)
{
    uint8_t tmp[32];
    if (!hex_to_bytes_fixed(hex, tmp, sizeof(tmp))) return false;
    memcpy(iot_group_key, tmp, sizeof(iot_group_key));
    p2p_secure_wipe(tmp, sizeof(tmp));
    iot_group_key_configured = true;
    return true;
}

bool crypto_persist_group_key(void)
{
    return iot_group_key_configured;
}

static void load_compiled_group_key(void)
{
    static const uint8_t mask[32] = P2P_COMPILED_GROUP_KEY_MASK_INIT;
    static const uint8_t xored[32] = P2P_COMPILED_GROUP_KEY_XOR_INIT;
    uint8_t tmp[32];

    if (iot_group_key_configured) return;
    for (size_t i = 0; i < sizeof(tmp); i++)
        tmp[i] = (uint8_t)(xored[i] ^ mask[i]);
    memcpy(iot_group_key, tmp, sizeof(iot_group_key));
    p2p_secure_wipe(tmp, sizeof(tmp));
    iot_group_key_configured = true;
}

bool crypto_control_get_pubkey(uint8_t pubkey[CRYPTO_PUBKEY_LEN])
{
    if (!pubkey || P2P_COMPILED_CONTROL_PUBKEY_HEX[0] == '\0')
        return false;
    return hex_to_bytes_fixed(P2P_COMPILED_CONTROL_PUBKEY_HEX, pubkey,
                              CRYPTO_PUBKEY_LEN);
}

bool crypto_control_set_secret_hex(const char *hex)
{
    uint8_t input_secret[CRYPTO_SECKEY_LEN] = {0};
    uint8_t seed[CRYPTO_SEED_LEN] = {0};
    uint8_t derived_secret[CRYPTO_SECKEY_LEN] = {0};
    uint8_t derived_pubkey[CRYPTO_PUBKEY_LEN] = {0};
    uint8_t configured_pubkey[CRYPTO_PUBKEY_LEN] = {0};
    bool ok = false;

    if (!hex_to_bytes_fixed(hex, input_secret, sizeof(input_secret)))
        goto out;
    if (!crypto_control_get_pubkey(configured_pubkey))
        goto out;

    memcpy(seed, input_secret, sizeof(seed));
    crypto_eddsa_key_pair(derived_secret, derived_pubkey, seed);

    ok = memcmp(derived_pubkey, configured_pubkey,
                sizeof(configured_pubkey)) == 0;
    if (ok) {
        memcpy(control_ed25519_secret_key, derived_secret,
               sizeof(control_ed25519_secret_key));
        control_ed25519_secret_key_configured = true;
    } else {
        p2p_secure_wipe(control_ed25519_secret_key,
                        sizeof(control_ed25519_secret_key));
        control_ed25519_secret_key_configured = false;
    }

out:
    p2p_secure_wipe(input_secret, sizeof(input_secret));
    p2p_secure_wipe(seed, sizeof(seed));
    p2p_secure_wipe(derived_secret, sizeof(derived_secret));
    p2p_secure_wipe(derived_pubkey, sizeof(derived_pubkey));
    p2p_secure_wipe(configured_pubkey, sizeof(configured_pubkey));
    return ok;
}

static bool crypto_control_verify_configured(void)
{
    uint8_t pubkey[CRYPTO_PUBKEY_LEN];
    bool ok = crypto_control_get_pubkey(pubkey);
    p2p_secure_wipe(pubkey, sizeof(pubkey));
    return ok;
}

bool crypto_control_sign_configured(void)
{
    return control_ed25519_secret_key_configured &&
           crypto_control_verify_configured();
}

bool crypto_control_sign(const uint8_t *data, size_t len,
                         uint8_t sig[CRYPTO_SIG_LEN])
{
    if (!data || !sig || !crypto_control_sign_configured())
        return false;
    crypto_eddsa_sign(sig, control_ed25519_secret_key, data, len);
    return true;
}

bool crypto_control_verify(const uint8_t *data, size_t len,
                           const uint8_t sig[CRYPTO_SIG_LEN])
{
    uint8_t control_pubkey[CRYPTO_PUBKEY_LEN];
    bool ok = false;

    if (!data || !sig || !crypto_control_get_pubkey(control_pubkey))
        return false;
    ok = crypto_eddsa_check(sig, control_pubkey, data, len) == 0;
    p2p_secure_wipe(control_pubkey, sizeof(control_pubkey));
    return ok;
}

bool crypto_group_proof(const char *label, const uint8_t *data, size_t len,
                        uint8_t out[CRYPTO_HS_PROOF_LEN])
{
    if (!label || !data || !out || !iot_group_key_configured) return false;
    size_t label_len = strlen(label);
    if (label_len + len > 160) return false;

    uint8_t material[160];
    uint8_t digest[32];
    memcpy(material, label, label_len);
    memcpy(material + label_len, data, len);
    crypto_blake2b_keyed(digest, sizeof(digest),
                         iot_group_key, sizeof(iot_group_key),
                         material, label_len + len);
    memcpy(out, digest, CRYPTO_HS_PROOF_LEN);
    p2p_secure_wipe(material, sizeof(material));
    p2p_secure_wipe(digest, sizeof(digest));
    return true;
}

bool crypto_group_proof_verify(const char *label, const uint8_t *data,
                               size_t len,
                               const uint8_t proof[CRYPTO_HS_PROOF_LEN])
{
    uint8_t expected[CRYPTO_HS_PROOF_LEN];
    if (!proof || !crypto_group_proof(label, data, len, expected))
        return false;
    uint8_t diff = 0;
    for (int i = 0; i < CRYPTO_HS_PROOF_LEN; i++)
        diff |= (uint8_t)(expected[i] ^ proof[i]);
    p2p_secure_wipe(expected, sizeof(expected));
    return diff == 0;
}

static void load_group_key_from_config(void)
{
    if (iot_group_key_configured) return;
    load_compiled_group_key();
}

static void store64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static const uint8_t p2p_aead_ad[] = "p2p-iot-monocypher-v1";

bool crypto_sign(const uint8_t *data, size_t len,
                         uint8_t sig[CRYPTO_SIG_LEN])
{
    if (!data || !sig || !my_ed25519_secret_key_configured) return false;
    crypto_eddsa_sign(sig, my_ed25519_secret_key, data, len);
    return true;
}

bool crypto_verify(const uint8_t *data, size_t len,
                            const uint8_t *sig,
                            const uint8_t  pubkey[CRYPTO_PUBKEY_LEN])
{
    if (!data || !sig || !pubkey) return false;
    return crypto_eddsa_check(sig, pubkey, data, len) == 0;
}

bool crypto_make_x25519_keypair(uint8_t secret[CRYPTO_X25519_KEY_LEN],
                                uint8_t pubkey[CRYPTO_X25519_KEY_LEN])
{
    if (!secret || !pubkey) return false;
    if (!crypto_random_bytes(secret, CRYPTO_X25519_KEY_LEN))
        return false;
    crypto_x25519_public_key(pubkey, secret);
    return true;
}

bool crypto_derive_session_key(const uint8_t local_secret[CRYPTO_X25519_KEY_LEN],
                               const uint8_t peer_pubkey[CRYPTO_X25519_KEY_LEN],
                               const uint8_t local_identity[CRYPTO_PUBKEY_LEN],
                               const uint8_t peer_identity[CRYPTO_PUBKEY_LEN],
                               bool outbound,
                               uint8_t session_key[32])
{
    if (!local_secret || !peer_pubkey || !local_identity ||
        !peer_identity || !session_key)
        return false;

    uint8_t shared[32];
    crypto_x25519(shared, local_secret, peer_pubkey);

    uint8_t material[16 + 32 + CRYPTO_PUBKEY_LEN * 2];
    size_t off = 0;
    const char label[] = "p2p-pfs-v1";
    memcpy(material + off, label, sizeof(label));
    off += sizeof(label);
    memcpy(material + off, shared, sizeof(shared));
    off += sizeof(shared);

    const uint8_t *client_id = outbound ? local_identity : peer_identity;
    const uint8_t *server_id = outbound ? peer_identity : local_identity;
    memcpy(material + off, client_id, CRYPTO_PUBKEY_LEN);
    off += CRYPTO_PUBKEY_LEN;
    memcpy(material + off, server_id, CRYPTO_PUBKEY_LEN);
    off += CRYPTO_PUBKEY_LEN;
    crypto_blake2b_keyed(session_key, 32, iot_group_key, sizeof(iot_group_key),
                         material, off);
    p2p_secure_wipe(shared, sizeof(shared));
    p2p_secure_wipe(material, sizeof(material));
    return true;
}

bool crypto_seal_with_key(const uint8_t *plain, size_t plain_len,
                          uint8_t *sealed, uint64_t nonce,
                          const uint8_t key[32])
{
    if (!plain || !sealed || !key || plain_len > HPV_PKT_MAX) return false;
    memcpy(sealed, my_ed25519_pubkey, CRYPTO_NONCE_PREFIX_LEN);
    store64_le(sealed + CRYPTO_NONCE_PREFIX_LEN, nonce);
    crypto_aead_lock(sealed + CRYPTO_NONCE_LEN,
                     sealed + CRYPTO_NONCE_LEN + plain_len,
                     key, sealed,
                     p2p_aead_ad, sizeof(p2p_aead_ad) - 1,
                     plain, plain_len);
    return true;
}

bool crypto_open_with_key(const uint8_t *sealed, size_t sealed_len,
                          uint8_t *plain, size_t *plain_len,
                          const uint8_t key[32])
{
    if (!sealed || !plain || !plain_len || !key) return false;
    if (sealed_len < CRYPTO_SEAL_OVERHEAD) return false;
    size_t clen = sealed_len - CRYPTO_SEAL_OVERHEAD;
    if (clen > HPV_PKT_MAX) return false;

    const uint8_t *tag = sealed + CRYPTO_NONCE_LEN + clen;
    int rc = crypto_aead_unlock(plain, tag, key, sealed,
                                p2p_aead_ad, sizeof(p2p_aead_ad) - 1,
                                sealed + CRYPTO_NONCE_LEN, clen);
    if (rc != 0) return false;
    *plain_len = clen;
    return true;
}

bool crypto_derive_context_key(const char *label,
                               const uint8_t *a, size_t a_len,
                               const uint8_t *b, size_t b_len,
                               uint8_t out_key[32])
{
    if (!label || !out_key || !iot_group_key_configured) return false;
    size_t label_len = strlen(label);
    if ((a_len > 0 && !a) || (b_len > 0 && !b)) return false;
    if (label_len + a_len + b_len > 256) return false;

    uint8_t material[256];
    size_t off = 0;
    memcpy(material + off, label, label_len);
    off += label_len;
    if (a_len > 0) {
        memcpy(material + off, a, a_len);
        off += a_len;
    }
    if (b_len > 0) {
        memcpy(material + off, b, b_len);
        off += b_len;
    }

    crypto_blake2b_keyed(out_key, 32, iot_group_key, sizeof(iot_group_key),
                         material, off);
    p2p_secure_wipe(material, sizeof(material));
    return true;
}

int p2p_conn_write(P2PConn *ssl, const void *buf, int len)
{
    if (!ssl || ssl->fd < 0) return -1;
    ssize_t n;
    do {
        n = write(ssl->fd, buf, (size_t)len);
    } while (n < 0 && errno == EINTR);
    return n < 0 ? -1 : (int)n;
}

int p2p_conn_read(P2PConn *ssl, void *buf, int len)
{
    if (!ssl || ssl->fd < 0) return -1;
    ssize_t n;
    do {
        n = read(ssl->fd, buf, (size_t)len);
    } while (n < 0 && errno == EINTR);
    return n < 0 ? -1 : (int)n;
}

int p2p_conn_get_error(P2PConn *ssl, int ret)
{
    (void)ssl;
    if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return P2PCONN_ERROR_WANT_READ;
    return ret < 0 ? errno : 0;
}

int p2p_conn_shutdown(P2PConn *ssl)
{
    (void)ssl;
    return 1;
}

void p2p_conn_free(P2PConn *ssl)
{
    free(ssl);
}

void crypto_init(void)
{
    load_group_key_from_config();
    if (!iot_group_key_configured) {
        if (!crypto_random_bytes(iot_group_key, sizeof(iot_group_key))) {
            fprintf(stderr, "error: no entropy for ephemeral group key\n");
            exit(1);
        }
        fprintf(stderr, "warning: no compiled group key, using local ephemeral\n");
    }

    {
        uint8_t seed[CRYPTO_SEED_LEN];
        if (!crypto_create_ephemeral_identity_seed(seed)) {
            fprintf(stderr, "error: no entropy for ephemeral ed25519\n");
            exit(1);
        }
        p2p_secure_wipe(my_ed25519_secret_key, sizeof(my_ed25519_secret_key));
        p2p_secure_wipe(my_ed25519_pubkey, sizeof(my_ed25519_pubkey));
        crypto_eddsa_key_pair(my_ed25519_secret_key, my_ed25519_pubkey, seed);
        p2p_secure_wipe(seed, sizeof(seed));
        my_ed25519_secret_key_configured = true;
        my_ed25519_pubkey_configured = true;
    }

}

void p2p_print_local_identity(void)
{
    char pub_hex[CRYPTO_PUBKEY_LEN * 2 + 1];
    dht_id_t ephemeral_id = dht_id_from_pubkey(my_ed25519_pubkey);
    bytes_to_hex_fixed(my_ed25519_pubkey, CRYPTO_PUBKEY_LEN, pub_hex);
    printf("[IDENTITY] DHT ephemeral id: %s\n", dht_id2str(ephemeral_id));
    printf("[IDENTITY] Ed25519 ephemeral pubkey: %s\n", pub_hex);
}

void crypto_shutdown(void)
{
    p2p_secure_wipe(iot_group_key, sizeof(iot_group_key));
    p2p_secure_wipe(control_ed25519_secret_key,
                    sizeof(control_ed25519_secret_key));
    p2p_secure_wipe(my_ed25519_secret_key, sizeof(my_ed25519_secret_key));
    p2p_secure_wipe(my_ed25519_pubkey, sizeof(my_ed25519_pubkey));
    p2p_secure_wipe(&my_dht_id, sizeof(my_dht_id));
    iot_group_key_configured = false;
    control_ed25519_secret_key_configured = false;
    my_ed25519_secret_key_configured = false;
    my_ed25519_pubkey_configured = false;
}

P2PConn *p2p_conn_wrap_client(int fd)
{
    P2PConn *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;
    conn->fd = fd;
    return conn;
}

P2PConn *p2p_conn_wrap_server(int fd)
{
    P2PConn *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;
    conn->fd = fd;
    return conn;
}
