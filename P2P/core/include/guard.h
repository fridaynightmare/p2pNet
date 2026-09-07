#ifndef P2P_GUARD_H
#define P2P_GUARD_H

#include "common.h"

/*
 * Fixed-size defensive guardrails for small/private deployments.
 * This module rejects new work before it can grow queues or buffers.
 */

bool p2p_guard_accept_inbound(const struct sockaddr_in *addr,
                              const char **reason);
bool p2p_guard_allow_dht_store(node_id_t peer, const char **reason);
bool p2p_guard_allow_broadcast(size_t payload_len, int ttl,
                               const char **reason);
bool p2p_guard_under_pressure(void);
void p2p_guard_dump_status(void);

#endif /* P2P_GUARD_H */
