// iot_profile.c
// figures out what crap hardware we're running on
// and adjusts params so the thing doesn't crash
//
// basically: micro = potato, small = shitty, medium = ok, high = actual server

#include "common.h"

#include <sys/resource.h>
#include <sys/sysinfo.h>

static const char *profile_names[] = {
    "MICRO", "SMALL", "MEDIUM", "HIGH"
};

// params for each profile tier
// yeah we could make this a json file or whatever but who cares
// json parsing on a microcontroller? lmao no thanks

typedef struct {
    // HyParView stuff
    int na;            // target active neighbors
    int nb;            // max active neighbors
    int np;            // max passive neighbors
    int n0;            // min active for "healthy" network or whatever
    int ka;            // active samples in shuffle
    int kp;            // passive samples in shuffle
    int arwl;          // active random walk length
    int prwl;          // passive random walk length
    int mrwl;          // max random walk length
    int shuffle0;      // base shuffle interval
    int shuffle1;      // shuffle jitter max
    int join_interval;
    // gossip/dht
    int gossip_ttl;    // ttl for broadcast, higher = more spam
    // overlay
    int overlay_sessions; // max overlay sessions (adaptive for memory)
    // adaptive memory
    int backlog_size;     // gossip dedup backlog
    int reconnect_size;   // reconnect table size
} iot_params_t;

// tuned for ~10k nodes because that's what the spec said
//
// micro  - <128mb ram. basically a toaster. ttl=8 hits like 256 nodes
//          which is nowhere near 10k but device would die anyway. leaf node.
//          if ur running this on actual hardware this old, i salute you soldier
//
// small  - ttl=11 gets you ~2k nodes, with overlap maybe hits 10k eventually
//          perfect for that nokia 3310 you found in a drawer
//
// medium - the "normal" config. ttl=14 should cover 10k with fanout=3
//          what 99% of users should be using unless they're masochists
//
// high   - seed/gateway nodes. np=500 so it can remember lots of peers
//          and help the potato devices find each other :)
//          basically you're the chad carrying the team
static const iot_params_t profile_params[4] = {
    /* MICRO */
    {
        .na           =  4,
        .nb           =  6,
        .np           = 40,
        .n0           =  1,
        .ka           =  1,
        .kp           =  2,
        .arwl         =  2,
        .prwl         =  4,
        .mrwl         = 10,
        .shuffle0     = 180,
        .shuffle1     = 360,
        .join_interval= 120,
        .gossip_ttl   =  8,
        .overlay_sessions = 8,   // 8 sessions = ~320 KB
        .backlog_size     = 256, // 9 KB (vs 72 KB in HIGH)
        .reconnect_size   = 16,  // 0.4 KB (vs 3.3 KB in HIGH)
    },
    /* SMALL */
    {
        .na           =  7,
        .nb           = 12,
        .np           = 80,
        .n0           =  2,
        .ka           =  2,
        .kp           =  3,
        .arwl         =  3,
        .prwl         =  6,
        .mrwl         = 20,
        .shuffle0     = 120,
        .shuffle1     = 240,
        .join_interval=  90,
        .gossip_ttl   = 11,
        .overlay_sessions = 12,  // 12 sessions = ~480 KB
        .backlog_size     = 512, // 18 KB
        .reconnect_size   = 32,  // 0.8 KB
    },
    /* MEDIUM  (≈ default, expanded for 10k) */
    {
        .na           = 14,
        .nb           = 22,
        .np           = 200,
        .n0           =  2,
        .ka           =  2,
        .kp           =  4,
        .arwl         =  3,
        .prwl         =  8,
        .mrwl         = 30,
        .shuffle0     =  45,  // antes: 60 - 25% más rápido
        .shuffle1     =  90,  // antes: 120
        .join_interval=  45,  // antes: 60 - 25% más rápido
        .gossip_ttl   = 14,
        .overlay_sessions = 20,  // 20 sessions = ~800 KB
        .backlog_size     = 1024, // 36 KB
        .reconnect_size   = 64,   // 1.7 KB
    },
    /* HIGH */
    {
        .na           = 28,
        .nb           = 48,
        .np           = 500,
        .n0           =  4,
        .ka           =  4,
        .kp           =  6,
        .arwl         =  5,
        .prwl         = 12,
        .mrwl         = 40,
        .shuffle0     =  30,  // antes: 45 - 33% más rápido
        .shuffle1     =  60,  // antes: 90
        .join_interval=  30,  // antes: 45 - 33% más rápido
        .gossip_ttl   = 16,
        .overlay_sessions = 32,  // 32 sessions = ~1.3 MB (todos los peers encriptados)
        .backlog_size     = 2048, // 72 KB
        .reconnect_size   = 128,  // 3.3 KB
    },
};

// ============================================================
//  detective work: wtf hardware are we actually on?
// ============================================================

// read ram from /proc/meminfo because linux
// because nobody has time for complicated syscalls
static unsigned long iot_read_meminfo_kb(void)
{
#if defined(__linux__)
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;

    char line[128];
    unsigned long kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line + 9, "%lu", &kb);
            break;
        }
    }
    fclose(f);
    return kb;
#else
    // fallback if /proc is missing for some reason
    // (are you running this on windows? in WSL? why?)
    struct sysinfo si;
    if (sysinfo(&si) == 0)
        return (unsigned long)(si.totalram * si.mem_unit / 1024UL);
    return 0; // good luck buddy
#endif
}

// count cpus
static int iot_cpu_count(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
}

// how many fds can we open before the os yells at us
static int iot_max_fds(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
        return (int)rl.rlim_cur;
    return 1024; // just guess if getrlimit fails (yolo strategy)
}

// ============================================================
//  decide which tier of sadness we're in
// ============================================================

// pick profile based on ram, cpu, fds
// returns the worst of the three because bottlenecks
// (chain is only as strong as weakest link and all that)
static iot_profile_t iot_classify(unsigned long ram_mb, int cpus, int fds)
{
    iot_profile_t by_ram, by_cpu, by_fds;

    // check ram
    if      (ram_mb <  128) by_ram = IOT_PROFILE_MICRO;
    else if (ram_mb <  512) by_ram = IOT_PROFILE_SMALL;
    else if (ram_mb < 2048) by_ram = IOT_PROFILE_MEDIUM;
    else                    by_ram = IOT_PROFILE_HIGH;

    // check cpus
    if      (cpus <= 1) by_cpu = IOT_PROFILE_MICRO;
    else if (cpus <= 2) by_cpu = IOT_PROFILE_SMALL;
    else if (cpus <= 4) by_cpu = IOT_PROFILE_MEDIUM;
    else                by_cpu = IOT_PROFILE_HIGH;

    // check fds
    if      (fds <  256) by_fds = IOT_PROFILE_MICRO;
    else if (fds <  512) by_fds = IOT_PROFILE_SMALL;
    else if (fds < 1024) by_fds = IOT_PROFILE_MEDIUM;
    else                 by_fds = IOT_PROFILE_HIGH;

    // take the worst one because we're pessimists
    // (and because optimism gets you OOM killed)
    iot_profile_t result = by_ram;
    if (by_cpu  < result) result = by_cpu;
    if (by_fds  < result) result = by_fds;
    return result;
}

// ============================================================
//  apply the profile to global config vars
// ============================================================
// only change stuff if user didn't set it manually
// because we respect user choices (even when they're wrong)

// default values from state.c
#define P2P_DEFAULT_NA           10
#define P2P_DEFAULT_NB           25
#define P2P_DEFAULT_NP          200
#define P2P_DEFAULT_N0            2
#define P2P_DEFAULT_KA            2
#define P2P_DEFAULT_KP            4
#define P2P_DEFAULT_ARWL          3
#define P2P_DEFAULT_PRWL          8
#define P2P_DEFAULT_MRWL         30
#define P2P_DEFAULT_SHUFFLE0     60
#define P2P_DEFAULT_SHUFFLE1    120
#define P2P_DEFAULT_JOIN_INTERVAL 60

// apply only if still default
#define AUTOTUNE_IF_DEFAULT(var, default_val, profile_val) \
    do { if ((var) == (default_val)) (var) = (profile_val); } while (0)

static void apply_profile(iot_profile_t prof)
{
    const iot_params_t *p = &profile_params[prof];

    AUTOTUNE_IF_DEFAULT(na,           P2P_DEFAULT_NA,            p->na);
    AUTOTUNE_IF_DEFAULT(nb,           P2P_DEFAULT_NB,            p->nb);
    AUTOTUNE_IF_DEFAULT(np,           P2P_DEFAULT_NP,            p->np);
    AUTOTUNE_IF_DEFAULT(n0,           P2P_DEFAULT_N0,            p->n0);
    AUTOTUNE_IF_DEFAULT(ka,           P2P_DEFAULT_KA,            p->ka);
    AUTOTUNE_IF_DEFAULT(kp,           P2P_DEFAULT_KP,            p->kp);
    AUTOTUNE_IF_DEFAULT(arwl,         P2P_DEFAULT_ARWL,          p->arwl);
    AUTOTUNE_IF_DEFAULT(prwl,         P2P_DEFAULT_PRWL,          p->prwl);
    AUTOTUNE_IF_DEFAULT(mrwl,         P2P_DEFAULT_MRWL,          p->mrwl);
    AUTOTUNE_IF_DEFAULT(shuffle0,     P2P_DEFAULT_SHUFFLE0,      p->shuffle0);
    AUTOTUNE_IF_DEFAULT(shuffle1,     P2P_DEFAULT_SHUFFLE1,      p->shuffle1);
    AUTOTUNE_IF_DEFAULT(join_interval,P2P_DEFAULT_JOIN_INTERVAL, p->join_interval);
    AUTOTUNE_IF_DEFAULT(gossip_ttl,   P2P_DEFAULT_GOSSIP_TTL,    p->gossip_ttl);
    
    // Always apply overlay sessions (adaptive per profile)
    overlay_max_sessions = p->overlay_sessions;
    
    // Allocate adaptive memory structures
    if (!backlog) {
        backlog_max = p->backlog_size;
        backlog = calloc(backlog_max, sizeof(backlog_entry_t));
        if (!backlog) {
            fprintf(stderr, "FATAL: failed to allocate backlog (%d entries)\n", backlog_max);
            exit(1);
        }
    }
    
    if (!reconnect_table) {
        reconnect_max = p->reconnect_size;
        reconnect_table = calloc(reconnect_max, sizeof(reconnect_entry_t));
        if (!reconnect_table) {
            fprintf(stderr, "FATAL: failed to allocate reconnect_table (%d entries)\n", reconnect_max);
            exit(1);
        }
    }
}

// ============================================================
//  main entry point - the magic happens here
// ============================================================
// call this before normalize_config() or things will be weird
// like "node joins network and immediately explodes" weird
iot_profile_t p2p_iot_autotune(void)
{
    unsigned long ram_kb = iot_read_meminfo_kb();
    unsigned long ram_mb = (ram_kb > 0) ? (ram_kb / 1024UL) : 512UL; // assume 512mb if detection fails (reasonable i guess...)
    int cpus = iot_cpu_count();
    int fds  = iot_max_fds();

    iot_profile_t prof = iot_classify(ram_mb, cpus, fds);
    apply_profile(prof);

    net_log("ram=%lu cpu=%d fds=%d prof=%s na=%d nb=%d np=%d ttl=%d shuf=%d+%d bl=%d rc=%d",
            ram_mb, cpus, fds, profile_names[prof],
            na, nb, np, gossip_ttl, shuffle0, shuffle1, backlog_max, reconnect_max);

    return prof;
}
