#define _POSIX_C_SOURCE 200809L

#include "watchdog.h"
#include "bootstrap_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define WD_HEARTBEAT_TIMEOUT_SEC 20
#define WD_STARTUP_TIMEOUT_SEC   45
#define WD_SHUTDOWN_GRACE_SEC    3
#define WD_CRASH_WINDOW_SEC      60
#define WD_CRASH_LIMIT           8
#define WD_CRASH_COOLDOWN_SEC    60

// global config with defaults
WatchdogConfig wd_config = {
    .delay_initial = 1,
    .delay_max     = 10,
    .max_restarts  = 0,      // 0 = unlimited
    .enabled       = true,
};

// internal watchdog state
static pid_t  wd_child_pid  = -1;   // active child pid
static bool   wd_daemon_mode = false;
static const char *wd_log_path = NULL;
static const char *wd_pidfile_path = NULL;
static pid_t  wd_pidfile_owner = -1;
static int    wd_heartbeat_pipe[2] = { -1, -1 };
static volatile sig_atomic_t wd_stop_signal = 0;

static void wd_close_fd(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static void wd_close_heartbeat_pipe(void)
{
    wd_close_fd(&wd_heartbeat_pipe[0]);
    wd_close_fd(&wd_heartbeat_pipe[1]);
}

static void wd_pidfile_cleanup(void)
{
    if (wd_pidfile_path && wd_pidfile_owner == getpid())
        unlink(wd_pidfile_path);
}

// monotonic clock in secs
static long wd_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec;
}

// sleep with EINTR retry
static void wd_sleep(int secs)
{
    // prevent negative sleep and timeout loop
    if (secs <= 0) return;
    
    struct timespec rem = { .tv_sec = secs, .tv_nsec = 0 };
    int attempts = 0;
    while (nanosleep(&rem, &rem) == -1 && errno == EINTR) {
        // safety: break if rem hits 0 or after 100 tries
        if (++attempts > 100 || rem.tv_sec == 0) break;
    }
}

// forward term/int to child
static void wd_signal_handler(int sig)
{
    wd_stop_signal = sig;
    if (wd_child_pid > 0)
        kill(wd_child_pid, sig);
}

static void wd_install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = wd_signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);

    signal(SIGCHLD, SIG_DFL);
}

static int wd_open_cwd_log_target(void)
{
    return open("/dev/null", O_WRONLY | O_CLOEXEC);
}

static int wd_open_log_target(void)
{
    if (wd_log_path) {
        return open(wd_log_path,
                    O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                    0644);
    }

    return wd_open_cwd_log_target();
}

static int wd_redirect_stdio(void)
{
    int in_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) {
        return -1;
    }

    int out_fd = wd_open_log_target();
    if (out_fd < 0) {
        close(in_fd);
        return -1;
    }

    if (dup2(in_fd, STDIN_FILENO) < 0 ||
        dup2(out_fd, STDOUT_FILENO) < 0 ||
        dup2(out_fd, STDERR_FILENO) < 0) {
        close(in_fd);
        close(out_fd);
        return -1;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    close(in_fd);
    if (out_fd > STDERR_FILENO)
        close(out_fd);
    return 0;
}

static int wd_write_pidfile(void)
{
    if (!wd_pidfile_path)
        return 0;

    int fd = open(wd_pidfile_path,
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  0644);
    if (fd < 0) {
        return -1;
    }

    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
    if (len <= 0 || write(fd, buf, (size_t)len) != len) {
        close(fd);
        return -1;
    }

    close(fd);
    wd_pidfile_owner = getpid();
    return 0;
}

static int wd_prepare_heartbeat_pipe(void)
{
    wd_close_heartbeat_pipe();
    if (pipe(wd_heartbeat_pipe) < 0) {
        return -1;
    }

    for (int i = 0; i < 2; i++) {
        int flags = fcntl(wd_heartbeat_pipe[i], F_GETFD, 0);
        if (flags >= 0)
            fcntl(wd_heartbeat_pipe[i], F_SETFD, flags | FD_CLOEXEC);

        flags = fcntl(wd_heartbeat_pipe[i], F_GETFL, 0);
        if (flags >= 0)
            fcntl(wd_heartbeat_pipe[i], F_SETFL, flags | O_NONBLOCK);
    }
    return 0;
}

static void wd_drain_heartbeat(long *last_heartbeat, bool *saw_heartbeat)
{
    if (wd_heartbeat_pipe[0] < 0 || !last_heartbeat || !saw_heartbeat)
        return;

    char buf[64];
    for (;;) {
        ssize_t n = read(wd_heartbeat_pipe[0], buf, sizeof(buf));
        if (n > 0) {
            *last_heartbeat = wd_now();
            *saw_heartbeat = true;
            continue;
        }
        if (n == 0)
            return;
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        return;
    }
}

static const char *wd_signal_name(int sig)
{
    switch (sig) {
    case SIGTERM: return "SIGTERM";
    case SIGINT:  return "SIGINT";
    case SIGHUP:  return "SIGHUP";
    case SIGKILL: return "SIGKILL";
    case SIGABRT: return "SIGABRT";
    case SIGSEGV: return "SIGSEGV";
    default:      return "signal";
    }
}

static pid_t wd_spawn(void)
{
    if (wd_prepare_heartbeat_pipe() < 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0) {
        wd_close_heartbeat_pipe();
        return -1;
    }
    if (pid == 0) {
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT,  SIG_DFL);
        signal(SIGHUP,  SIG_DFL);
        wd_stop_signal = 0;
        wd_close_fd(&wd_heartbeat_pipe[0]);
        return 0;
    }
    wd_close_fd(&wd_heartbeat_pipe[1]);
    return pid;
}

static void wd_loop(void)
{
    int restarts  = 0;
    int delay     = wd_config.delay_initial;
    long crash_window_started = 0;
    int  crash_window_restarts = 0;

    wd_install_signals();

    for (;;) {
        long t_start = wd_now();

        wd_child_pid = wd_spawn();
        if (wd_child_pid < 0) {
            fprintf(stderr, "fork() failed, retrying in %ds...\n", delay);
            wd_sleep(delay);
            continue;
        }

        if (wd_child_pid == 0)
            return;

        int status = 0;
        bool saw_heartbeat = false;
        bool restart_requested = false;
        bool term_sent = false;
        bool kill_sent = false;
        long last_heartbeat = t_start;
        long action_deadline = 0;

        for (;;) {
            pid_t dead = waitpid(wd_child_pid, &status, WNOHANG);
            if (dead == wd_child_pid)
                break;
            if (dead < 0) {
                if (errno == EINTR)
                    continue;
                restart_requested = true;
                if (wd_child_pid > 0 && !kill_sent) {
                    kill(wd_child_pid, SIGKILL);
                    kill_sent = true;
                }
            }

            wd_drain_heartbeat(&last_heartbeat, &saw_heartbeat);

            long now = wd_now();
            if (wd_stop_signal) {
                if (!term_sent && wd_child_pid > 0) {
                    fprintf(stderr, "shutdown requested (%s), sending term to child\n",
                            wd_signal_name((int)wd_stop_signal));
                    kill(wd_child_pid, SIGTERM);
                    term_sent = true;
                    action_deadline = now + WD_SHUTDOWN_GRACE_SEC;
                } else if (term_sent && !kill_sent &&
                           now >= action_deadline && wd_child_pid > 0) {
                    fprintf(stderr, "child won't die, sending kill\n");
                    kill(wd_child_pid, SIGKILL);
                    kill_sent = true;
                }
            } else if (!restart_requested) {
                if (!saw_heartbeat &&
                    now - t_start >= WD_STARTUP_TIMEOUT_SEC && wd_child_pid > 0) {
                    fprintf(stderr, "no hb after %ds, restart\n",
                            WD_STARTUP_TIMEOUT_SEC);
                    kill(wd_child_pid, SIGTERM);
                    restart_requested = true;
                    term_sent = true;
                    action_deadline = now + WD_SHUTDOWN_GRACE_SEC;
                } else if (saw_heartbeat &&
                           now - last_heartbeat >= WD_HEARTBEAT_TIMEOUT_SEC &&
                           wd_child_pid > 0) {
                    fprintf(stderr, "hb expired %lds, restart\n",
                            now - last_heartbeat);
                    kill(wd_child_pid, SIGTERM);
                    restart_requested = true;
                    term_sent = true;
                    action_deadline = now + WD_SHUTDOWN_GRACE_SEC;
                }
            } else if (term_sent && !kill_sent &&
                       now >= action_deadline && wd_child_pid > 0) {
                fprintf(stderr, "child not responding, kill\n");
                kill(wd_child_pid, SIGKILL);
                kill_sent = true;
            }

            if (wd_heartbeat_pipe[0] >= 0) {
                struct pollfd pfd;
                memset(&pfd, 0, sizeof(pfd));
                pfd.fd = wd_heartbeat_pipe[0];
                pfd.events = POLLIN | POLLHUP;
                (void)poll(&pfd, 1, 1000);
            } else {
                wd_sleep(1);
            }
        }

        long uptime = wd_now() - t_start;
        wd_close_heartbeat_pipe();
        wd_child_pid = -1;

        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            fprintf(stderr, "child exit(%d) uptime=%lds\n",
                    code, uptime);

            if (code == P2P_EXIT_CLEAN) {
                fprintf(stderr, "clean exit, shutting down\n");
                wd_pidfile_cleanup();
                exit(P2P_EXIT_CLEAN);
            }
            if (code == P2P_EXIT_FATAL) {
                wd_pidfile_cleanup();
                fprintf(stderr, "error: invalid config\n");
                exit(P2P_EXIT_FATAL);
            }

        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            fprintf(stderr, "child signal %d (%s) uptime=%lds\n",
                    sig, wd_signal_name(sig), uptime);

            if (wd_stop_signal && (sig == SIGTERM || sig == SIGKILL)) {
                fprintf(stderr, "shutdown ok, shutting down\n");
                wd_pidfile_cleanup();
                exit(P2P_EXIT_CLEAN);
            }

            if (!restart_requested && sig == SIGTERM) {
                fprintf(stderr, "term signal forwarded, shutting down\n");
                wd_pidfile_cleanup();
                exit(P2P_EXIT_CLEAN);
            }
        }

        restarts++;
        if (wd_config.max_restarts > 0 && restarts >= wd_config.max_restarts) {
            wd_pidfile_cleanup();
            fprintf(stderr, "error: max restarts exceeded\n");
            exit(P2P_EXIT_RESTART);
        }

        if (crash_window_started == 0 ||
            t_start - crash_window_started > WD_CRASH_WINDOW_SEC) {
            crash_window_started = t_start;
            crash_window_restarts = 0;
        }
        crash_window_restarts++;

        if (uptime >= (long)wd_config.delay_max) {
            delay = wd_config.delay_initial;
            fprintf(stderr, "long uptime %lds, backoff reset\n",
                    uptime);
        }

        if (crash_window_restarts >= WD_CRASH_LIMIT) {
            fprintf(stderr, "too many restarts in %ds, cooling down %ds\n",
                    WD_CRASH_WINDOW_SEC, WD_CRASH_COOLDOWN_SEC);
            wd_sleep(WD_CRASH_COOLDOWN_SEC);
            crash_window_started = wd_now();
            crash_window_restarts = 0;
            delay = wd_config.delay_initial;
            continue;
        }

        fprintf(stderr, "relaunching in %ds... restart #%d\n",
                delay, restarts);
        wd_sleep(delay);

        delay *= 2;
        if (delay > wd_config.delay_max)
            delay = wd_config.delay_max;
    }
}

void watchdog_set_daemon_mode(bool daemon_mode,
                              const char *log_path,
                              const char *pidfile_path)
{
    wd_daemon_mode = daemon_mode;
    wd_log_path = log_path;
    wd_pidfile_path = pidfile_path;
}

bool watchdog_is_daemon_mode(void)
{
    return wd_daemon_mode;
}

void watchdog_heartbeat(void)
{
    if (wd_heartbeat_pipe[1] < 0)
        return;

    char byte = 'H';
    ssize_t n;
    do {
        n = write(wd_heartbeat_pipe[1], &byte, 1);
    } while (n < 0 && errno == EINTR);
}

int watchdog_detach_terminal(void)
{
    if (!wd_daemon_mode)
        return 0;

    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid > 0)
        _exit(0);

    if (setsid() < 0) {
        return -1;
    }

    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid > 0)
        _exit(0);

    umask(027);

    if (wd_redirect_stdio() < 0)
        return -1;

    if (wd_write_pidfile() < 0)
        return -1;

    atexit(wd_pidfile_cleanup);
    return 0;
}

void watchdog_enter(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    if (!wd_config.enabled)
        return;

    wd_loop();

}
