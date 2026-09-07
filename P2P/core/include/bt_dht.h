#ifndef P2P_BT_DHT_H
#define P2P_BT_DHT_H

// bt_dht.h — bootstrap via bittorrent's public dht (bep5)
//
// uses bittorrent's public dht only for discovery. the flow:
//
//   1. derive infohash from group key:
//         infohash = sha256(group_key || "p2p-bt-bootstrap-v1")[0:20]
//      only nodes with same group key find same infohash
//
//      since p2p_v3 infohash rotates daily (hajime style):
//         infohash = sha256(group_key || "p2p-bt-v2-yyyy-mm-dd\0")[0:20]
//      rotates at midnight utc
//      all nodes with same key derive same value each day
//
//   2. contact public bt bootstrap nodes (router.bittorrent.com etc)
//      via udp + bencoding (bep5)
//
//   3. do get_peers(infohash)
//
//   4. do announce_peer(infohash, own_port)
//
//   5. hand each found ip:port to dht_bootstrap() and add_passive()
//      from internal protocol
//
// module runs in its own thread (bt_dht_thread) and talks to the rest
// only through dht_bootstrap() and add_passive(), which are thread-safe
// by design (only write to ps[] under conn_mutex and to dht_routing_table
// under internal dht lock)
//
// external protocol: plain udp with standard bep5 bencoding
// internal protocol: usual encrypted node handshake
// usage:
//   bt_dht_init(local_port, group_key_32bytes);
//   bt_dht_start();
//   ...
//   bt_dht_stop();

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "bootstrap_config.h"

#define BT_BOOTSTRAP_COUNT  P2P_BT_DHT_BOOTSTRAP_NODE_COUNT

#define BT_REFRESH_INTERVAL  60

#define BT_QUERY_TIMEOUT     5

#define BT_MAX_PEERS         64

#define BT_ROUTING_MAX       128

#define BT_UDP_PORT_DEFAULT  0

// init the module. call BEFORE bt_dht_start()
//
//   local_port   : node's tcp port (also used as udp port)
//                  if 0 uses p2p_default_port
//   group_key_32 : 32 bytes of group key (crypto_get_group_key)
//                  if null infohash derived from zeros (isolated network)
void bt_dht_init(int local_port, const uint8_t *group_key_32);

// launches bt bootstrap thread. doesn't block
// if already running does nothing
void bt_dht_start(void);

// signals thread to stop and waits for it to finish
// safe to call even if bt_dht_start() never called
void bt_dht_stop(void);

#endif /* P2P_BT_DHT_H */
