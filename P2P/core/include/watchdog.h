#ifndef P2P_WATCHDOG_H
#define P2P_WATCHDOG_H

/*
 * p2p_watchdog — parent/child process watchdog thing
 *
 * forks on startup:
 *   - parent  → watchdog; just monitors and relaunches
 *   - child   → all the p2p logic (what main does now)
 *
 * if child dies (crash, oom-killer, sigkill, whatever)
 * parent relaunches it with exponential backoff
 * if child exits with P2P_EXIT_CLEAN parent does NOT relaunch
 *
 * usage in main.c:
 *
 *   int main(int argc, char *argv[]) {
 *       watchdog_enter(argc, argv);
 *
 *       ...
 *   }
 *
 * exit codes child can use that watchdog cares about:
 *   P2P_EXIT_CLEAN   (0)
 *   P2P_EXIT_RESTART (1)
 *   P2P_EXIT_FATAL   (2)
 *   anything else
 */

#include <stdbool.h>

// exit codes for watchdog
#define P2P_EXIT_CLEAN    0
#define P2P_EXIT_RESTART  1
#define P2P_EXIT_FATAL    2

typedef struct {
    int  delay_initial;
    int  delay_max;
    int  max_restarts;
    bool enabled;
} WatchdogConfig;

/* global config; change it before calling watchdog_enter() or whatever */
extern WatchdogConfig wd_config;

/*
 * sets up detached terminal startup
 *
 * - daemon_mode=false: doesn't do anything special
 * - log_path=NULL: stdout/stderr go to ./p2p_agent.log
 * - pidfile_path=NULL: no pidfile written
 */
void watchdog_set_daemon_mode(bool daemon_mode,
                              const char *log_path,
                              const char *pidfile_path);

/*
 * runs daemonization sequence if requested with
 * watchdog_set_daemon_mode()
 *
 * call this before watchdog_enter()
 *
 * returns 0 if ok, -1 on error
 */
int watchdog_detach_terminal(void);

bool watchdog_is_daemon_mode(void);

/*
 * child should call this periodically while it's still alive and doing stuff
 * if watchdog stops receiving heartbeats within timeout
 * it assumes hang and forces restart
 */
void watchdog_heartbeat(void);

/*
 * watchdog_enter() — forks the process
 *
 * - if wd_config.enabled == false: does nothing, returns immediately
 * - child process returns from this function (continues as p2p node)
 * - parent process enters supervision loop and NEVER returns
 *
 * argc/argv saved to relaunch child with same args
 * (child inherits exactly same args that main() got)
 */
void watchdog_enter(int argc, char *argv[]);

#endif /* P2P_WATCHDOG_H */
