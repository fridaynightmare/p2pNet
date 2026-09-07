#include "common.h"
#include <stdarg.h>

// terminal colors
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_RED     "\033[31m"
#define C_BRED    "\033[91m"
#define C_GREEN   "\033[32m"
#define C_BGREEN  "\033[92m"
#define C_YELLOW  "\033[33m"
#define C_BCYAN   "\033[96m"
#define C_GRAY    "\033[90m"

static bool g_colors = false;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool is_runtime_info_log(const char *msg)
{
    static const char *allowed[] = {
        "Command received successfully",
        "Module received successfully",
        "Shutting down agent",
        "[WD]",
        "[NODE]",
        "[MC-MINER] status:",
        "[MC-MINER] start: launcher",
        "[MC-MINER] stop:",
        "[MC-MINER] usage:",
        "[MC-MINER] unknown subcommand:",
        "Agent starting:",
        "Overlay UDP active",
        "BT-DHT bootstrap enabled",
        "BT-DHT disabled",
        "TCP listening",
        NULL
    };

    for (int i = 0; allowed[i]; i++)
        if (strstr(msg, allowed[i])) return true;
    return false;
}

static void colors_init(void)
{
    static bool done = false;
    if (done) return;
    done    = true;
    g_colors = isatty(STDOUT_FILENO);
}

// print timestamp
static void print_ts(void)
{
    time_t     now = time(NULL);
    struct tm *tm  = localtime(&now);
    if (g_colors)
        printf("%s%02d:%02d:%02d%s ",
               C_GRAY, tm->tm_hour, tm->tm_min, tm->tm_sec, C_RESET);
    else
        printf("%02d:%02d:%02d ",
               tm->tm_hour, tm->tm_min, tm->tm_sec);
}

typedef enum {
    LVL_DEBUG = 0,
    LVL_INFO,
    LVL_SUCCESS,
    LVL_WARN,
    LVL_ERROR
} log_level_t;

// figure out log level from message keywords
static log_level_t detect_level(const char *msg)
{
    static const char *err_kw[] = {
        "invalid", "failed", "revoked", "[PFS]", "[TRUST]",
        "[CRYPTO]", "[POW]", "MAC/cipher", "socket error",
        "no PFS", "strong RNG", "Write error", "Could not",
        "could not",
        "missing ", "fork failed", "waitpid(",
        NULL
    };
    for (int i = 0; err_kw[i]; i++)
        if (strstr(msg, err_kw[i])) return LVL_ERROR;

    static const char *warn_kw[] = {
        "full", "reject", "redirect", "[RATE]",
        "discarded", "disconnected", "Reforming", "Timeout",
        "timeout", "shutdown", "disabled", "non-public",
        "inactive", "expelling", "no activity", "expired",
        NULL
    };
    for (int i = 0; warn_kw[i]; i++)
        if (strstr(msg, warn_kw[i])) return LVL_WARN;

    static const char *ok_kw[] = {
        "Command received successfully",
        "Module received successfully",
        NULL
    };
    for (int i = 0; ok_kw[i]; i++)
        if (strstr(msg, ok_kw[i])) return LVL_SUCCESS;

    return LVL_INFO;
}

static void print_level_prefix(const char *tag, log_level_t lvl)
{
    if (!g_colors) {
        printf("[%s] ", tag);
        return;
    }
    switch (lvl) {
    case LVL_ERROR:
        printf("%s%s[%s]%s ", C_BOLD, C_BRED,  tag, C_RESET); break;
    case LVL_WARN:
        printf("%s[%s]%s ", C_YELLOW, tag, C_RESET);           break;
    case LVL_SUCCESS:
        printf("%s[%s]%s ", C_BGREEN, tag, C_RESET);           break;
    case LVL_DEBUG:
        printf("%s[%s]%s ", C_GRAY,   tag, C_RESET);           break;
    default: // info level
        printf("%s[%s]%s ", C_BCYAN,  tag, C_RESET);           break;
    }
}

static void shorten_log_message(char *msg)
{
    enum { LOG_PREVIEW_MAX = 220 };
    size_t len = strlen(msg);
    if (len <= LOG_PREVIEW_MAX) return;

    char suffix[48];
    snprintf(suffix, sizeof(suffix), "... [%zu bytes]", len);
    size_t suffix_len = strlen(suffix);
    if (suffix_len >= LOG_PREVIEW_MAX) return;

    memcpy(msg + LOG_PREVIEW_MAX - suffix_len, suffix, suffix_len + 1);
}

static void print_msg_colored(log_level_t lvl, const char *msg)
{
    if (!g_colors) {
        printf("%s\n", msg);
        return;
    }
    switch (lvl) {
    case LVL_ERROR:   printf("%s%s%s\n", C_RED,    msg, C_RESET); break;
    case LVL_WARN:    printf("%s%s%s\n", C_YELLOW, msg, C_RESET); break;
    case LVL_SUCCESS: printf("%s%s%s\n", C_GREEN,  msg, C_RESET); break;
    case LVL_DEBUG:   printf("%s%s%s\n", C_GRAY,   msg, C_RESET); break;
    default:          printf("%s\n", msg);                          break;
    }
}

// log functions, disabled anyway

void net_log(const char *fmt, ...)
{
    // Enable logging for operator mode
    extern bool p2p_operator_mode;
    if (p2p_operator_mode) {
        va_list args;
        va_start(args, fmt);
        
        // Add timestamp
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S]", tm_info);
        
        printf("%s ", timestamp);
        vprintf(fmt, args);
        printf("\n");
        fflush(stdout);
        
        va_end(args);
    }
}

void dht_log(const char *fmt, ...)
{
    // Enable DHT logging for operator mode  
    extern bool p2p_operator_mode;
    if (p2p_operator_mode) {
        va_list args;
        va_start(args, fmt);
        
        // Add timestamp and DHT prefix
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S]", tm_info);
        
        printf("%s [DHT] ", timestamp);
        vprintf(fmt, args);
        printf("\n");
        fflush(stdout);
        
        va_end(args);
    }
}

// utils

int id_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

static bool ipv4_in_cidr(uint32_t ip, uint8_t a, uint8_t b, uint8_t c,
                         uint8_t d, uint8_t prefix)
{
    uint32_t base = ((uint32_t)a << 24) |
                    ((uint32_t)b << 16) |
                    ((uint32_t)c << 8)  |
                    (uint32_t)d;
    uint32_t mask = prefix == 0 ? 0 : (UINT32_MAX << (32 - prefix));
    return (ip & mask) == (base & mask);
}

bool p2p_ipv4_is_public(uint32_t ip_net)
{
    uint32_t ip = ntohl(ip_net);

    if (ipv4_in_cidr(ip, 0,   0,   0,   0,  8)) return false;
    if (ipv4_in_cidr(ip, 10,  0,   0,   0,  8)) return false;
    if (ipv4_in_cidr(ip, 100, 64,  0,   0, 10)) return false;
    if (ipv4_in_cidr(ip, 127, 0,   0,   0,  8)) return false;
    if (ipv4_in_cidr(ip, 169, 254, 0,   0, 16)) return false;
    if (ipv4_in_cidr(ip, 172, 16,  0,   0, 12)) return false;
    if (ipv4_in_cidr(ip, 192, 0,   0,   0, 24)) return false;
    if (ipv4_in_cidr(ip, 192, 0,   2,   0, 24)) return false;
    if (ipv4_in_cidr(ip, 192, 88,  99,  0, 24)) return false;
    if (ipv4_in_cidr(ip, 192, 168, 0,   0, 16)) return false;
    if (ipv4_in_cidr(ip, 198, 18,  0,   0, 15)) return false;
    if (ipv4_in_cidr(ip, 198, 51,  100, 0, 24)) return false;
    if (ipv4_in_cidr(ip, 203, 0,   113, 0, 24)) return false;
    if (ipv4_in_cidr(ip, 224, 0,   0,   0,  4)) return false;
    if (ipv4_in_cidr(ip, 240, 0,   0,   0,  4)) return false;

    return true;
}

bool p2p_node_id_is_public(node_id_t id)
{
    uint32_t ip;
    uint16_t port;

    memcpy(&ip, id.id, 4);
    memcpy(&port, id.id + 4, 2);
    if (port == 0) return false;
    return p2p_ipv4_is_public(ip);
}

bool node_id_from_ip_port(const char *ip, int port, node_id_t *out)
{
    if (!ip || !out || port <= 0 || port > 65535) return false;
    memset(out, 0, sizeof(*out));
    if (inet_aton(ip, (struct in_addr *)out->id) == 0) return false;
    uint16_t port_net = htons((uint16_t)port);
    memcpy(out->id + 4, &port_net, 2);
    if (!p2p_node_id_is_public(*out)) return false;
    return true;
}

bool is_self_node(node_id_t id)
{
    uint32_t ip;
    uint16_t port;

    memcpy(&ip, id.id, 4);
    memcpy(&port, id.id + 4, 2);

    if (ntohs(port) != my_listen_port) return false;

    if (ntohl(ip) == INADDR_LOOPBACK || ntohl(ip) == INADDR_ANY) return true;

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) return false;

    bool match = false;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        if (sa->sin_addr.s_addr == ip) {
            match = true;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return match;
}

char *id2str(node_id_t id)
{
    static char pool[16][32];
    static int  slot = 0;
    char *str = pool[slot & 15]; slot++;
    struct in_addr addr;
    uint16_t port;
    memcpy(&addr, id.id, 4);
    memcpy(&port, id.id + 4, 2);
    snprintf(str, 32, "%s:%d", inet_ntoa(addr), ntohs(port));
    return str;
}

ssize_t write_all(int fd, P2PConn *ssl, const uint8_t *buf, size_t len)
{
    if (ssl) {
        size_t written = 0;
        while (written < len) {
            int n = p2p_conn_write(ssl, buf+written, (int)(len-written));
            if (n <= 0) {
                int err = p2p_conn_get_error(ssl, n);
                if (err == P2PCONN_ERROR_WANT_WRITE ||
                    err == P2PCONN_ERROR_WANT_READ) continue;
                return -1;
            }
            written += (size_t)n;
        }
        return (ssize_t)written;
    }
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, buf+written, len-written);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        written += (size_t)n;
    }
    return (ssize_t)written;
}

ssize_t read_from(int fd, P2PConn *ssl, uint8_t *buf, size_t len)
{
    if (ssl) {
        int n = p2p_conn_read(ssl, buf, (int)len);
        if (n < 0) return -1;
        if (n == 0) return 0;
        return (ssize_t)n;
    }
    return read(fd, buf, len);
}

// detect cpu from macros or /proc/cpuinfo
static bool p2p_detect_arch_compile_time(char out[16])
{
#if defined(__mips__) && !defined(__mips64) && !defined(__mips64__)
# if defined(__MIPSEL__) || defined(_MIPSEL) || \
    (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    snprintf(out, 16, "MIPS32EL");
# else
    snprintf(out, 16, "MIPS32");
# endif
    return true;
#elif defined(__mips64) || defined(__mips64__)
    snprintf(out, 16, "MIPS64");
    return true;
#elif defined(__arm__) && (defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7__) || \
                           defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || \
                           defined(__ARM_ARCH_7S__) || defined(__target_armv7l__))
    snprintf(out, 16, "ARMv7");
    return true;
#elif defined(__aarch64__) || defined(_M_ARM64)
    snprintf(out, 16, "ARM64");
    return true;
#elif defined(__arm__) || defined(_M_ARM)
    snprintf(out, 16, "ARM32");
    return true;
#elif defined(__i386__) || defined(_M_IX86)
    snprintf(out, 16, "x86");
    return true;
#elif defined(__x86_64__) || defined(_M_X64)
    snprintf(out, 16, "x86_64");
    return true;
#elif defined(__riscv)
# if defined(__riscv_xlen) && (__riscv_xlen == 64)
    snprintf(out, 16, "RISCV64");
# else
    snprintf(out, 16, "RISCV32");
# endif
    return true;
#elif defined(__xtensa__)
    snprintf(out, 16, "XTENSA");
    return true;
#elif defined(__AVR__)
    snprintf(out, 16, "AVR");
    return true;
#elif defined(__powerpc64__) || defined(__powerpc64le__) || defined(__powerpc__)
    snprintf(out, 16, "PowerPC");
    return true;
#else
    (void)out;
    return false;
#endif
}

static bool p2p_detect_arch_cpuinfo(char out[16])
{
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncasecmp(line, "CPU architecture", 16) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                int v = atoi(colon + 1);
                fclose(fp);
                if (v >= 8)
                    snprintf(out, 16, "ARM64");
                else if (v == 7)
                    snprintf(out, 16, "ARMv7");
                else
                    snprintf(out, 16, "ARM32");
                return true;
            }
        }
        if (strncasecmp(line, "model name", 10) == 0) {
            if (strcasestr(line, "aarch64") || strcasestr(line, "arm64")) {
                fclose(fp);
                snprintf(out, 16, "ARM64");
                return true;
            }
            if (strcasestr(line, "armv7")) {
                fclose(fp);
                snprintf(out, 16, "ARMv7");
                return true;
            }
            if (strcasestr(line, "arm")) {
                fclose(fp);
                snprintf(out, 16, "ARM32");
                return true;
            }
            if (strcasestr(line, "intel") || strcasestr(line, "amd") ||
                strcasestr(line, "x86")) {
                fclose(fp);
                FILE *fp2 = fopen("/proc/cpuinfo", "r");
                if (fp2) {
                    char l2[512];
                    while (fgets(l2, sizeof(l2), fp2)) {
                        if (strncasecmp(l2, "flags", 5) == 0 ||
                            strncasecmp(l2, "Features", 8) == 0) {
                            if (strstr(l2, " lm ") || strstr(l2, " lm\n")) {
                                fclose(fp2);
                                snprintf(out, 16, "x86_64");
                                return true;
                            }
                            break;
                        }
                    }
                    fclose(fp2);
                }
                snprintf(out, 16, "x86");
                return true;
            }
        }
        if (strncasecmp(line, "cpu model", 9) == 0) {
            if (strcasestr(line, "mips64") || strcasestr(line, "mips 64")) {
                fclose(fp);
                snprintf(out, 16, "MIPS64");
                return true;
            }
            if (strcasestr(line, "mips")) {
                fclose(fp);
                snprintf(out, 16, "MIPS32");
                return true;
            }
        }
        if (strcasestr(line, "riscv64")) {
            fclose(fp);
            snprintf(out, 16, "RISCV64");
            return true;
        }
        if (strcasestr(line, "riscv32")) {
            fclose(fp);
            snprintf(out, 16, "RISCV32");
            return true;
        }
        if (strcasestr(line, "riscv")) {
            fclose(fp);
            snprintf(out, 16, "RISCV32");
            return true;
        }
        if (strncasecmp(line, "cpu", 3) == 0 && strcasestr(line, "powerpc")) {
            fclose(fp);
            snprintf(out, 16, "PowerPC");
            return true;
        }
    }

    fclose(fp);
    return false;
}

void p2p_detect_arch(char out[16])
{
    if (p2p_detect_arch_compile_time(out)) {
        return;
    }
    if (p2p_detect_arch_cpuinfo(out)) {
        return;
    }
    snprintf(out, 16, "Unknown");
}
