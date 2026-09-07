#ifndef P2P_OVERLAY_H
#define P2P_OVERLAY_H

// overlay.h
//
// app layer on top of UDP transport. handles handshake, requests, responses, pex
//
//   ┌─────────────────────────────────────────┐
//   │       application protocol layer         │  ← this module
//   │  (Handshake, Request, Response, PEX)     │
//   ├─────────────────────────────────────────┤
//   │     UDP Custom Transport (Reliable)      │  ← udp.c
//   ├─────────────────────────────────────────┤
//   │               UDP (socket)               │
//   └─────────────────────────────────────────┘
//
// wire format:
//
//   Offset  Size    Field
//   ------  ------  -----
//      0      4     Length  (rest of the message)
//      4      1     Type    (operation type)
//      5      N     Payload
//
// initial handshake is cleartext to negotiate peer ids. after that,
// all messages use AEAD:
//   Counter64(8) + Ciphertext(N) + MAC(16)
//
// receiver keeps highest accepted counter per session and rejects
// old or duplicate counters
//
// message types:
//   0x00 – Handshake:      Magic(6) + Version(2) + PeerID(20)
//   0x01 – Request:        InfoHash(20) + Offset(4) + Length(4)
//   0x02 – Response:       InfoHash(20) + Offset(4) + Data(N)
//   0x03 – PeerExchange:   Count(2) + [ IP(4) + Port(2) + NodeID(20) ] * N
//
// AEAD key derived from compiled group key + local/remote peer ids

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

// protocol constants

#define OVERLAY_MAGIC          "MAGIC!"
#define OVERLAY_MAGIC_LEN      6
#define OVERLAY_VERSION        0x0100u
#define OVERLAY_PEER_ID_LEN    20
#define OVERLAY_INFOHASH_LEN   20
#define OVERLAY_CRYPTO_MAC_LEN 16
#define OVERLAY_CRYPTO_CTR_LEN 8
#define OVERLAY_CRYPTO_OVERHEAD (OVERLAY_CRYPTO_CTR_LEN + OVERLAY_CRYPTO_MAC_LEN)

// overlay message types
#define OVERLAY_MSG_HANDSHAKE  0x00
#define OVERLAY_MSG_REQUEST    0x01
#define OVERLAY_MSG_RESPONSE   0x02
#define OVERLAY_MSG_PEX        0x03       // peer exchange
#define OVERLAY_MSG_KEEPALIVE  0x04

#define OVERLAY_HS_PAYLOAD     (OVERLAY_MAGIC_LEN + 2 + OVERLAY_PEER_ID_LEN)
#define OVERLAY_REQ_PAYLOAD    (OVERLAY_INFOHASH_LEN + 4 + 4)
#define OVERLAY_RESP_HDR       (OVERLAY_INFOHASH_LEN + 4)
#define OVERLAY_PEX_ENTRY_SIZE (4 + 2 + 20)
#define OVERLAY_PEX_MAX        32

// Maximum overlay sessions (array size at compile time)
#define OVERLAY_MAX_SESSIONS_HARD  64  // Array size (worst case)

// Actual limit is adaptive based on IoT profile (set in iot_profile.c)
// MICRO: 8, SMALL: 12, MEDIUM: 20, HIGH: 32
// Only uses what's needed, rest of array stays unused
extern int overlay_max_sessions;

#define OVERLAY_CHUNK_MAX      (8 * 1024)  // Reduced from 60KB to 8KB for IoT devices

#define OVERLAY_MAX_SESSIONS   64

// handshake timeout in seconds
#define OVERLAY_HS_TIMEOUT     10

#define OVERLAY_SESSION_TIMEOUT 120

#define OVERLAY_RECONNECT_INTERVAL      5
#define OVERLAY_RECONNECT_MAX_ATTEMPTS  8
#define OVERLAY_RECONNECT_BACKOFF_BASE  2
#define OVERLAY_RECONNECT_BACKOFF_MAX   60
#define OVERLAY_KEEPALIVE_INTERVAL      30
#define OVERLAY_PENDING_MSG_MAX         4  // Reduced from 16 to 4 for memory

// structs

typedef enum {
    OVERLAY_SESS_FREE        = 0,
    OVERLAY_SESS_HANDSHAKING = 1,
    OVERLAY_SESS_ESTABLISHED = 2,
    OVERLAY_SESS_CLOSING     = 3,
    OVERLAY_SESS_RECONNECTING = 4
} overlay_sess_state_t;

typedef struct {
    uint8_t  data[5 + OVERLAY_CHUNK_MAX + OVERLAY_RESP_HDR + 
                  OVERLAY_CRYPTO_OVERHEAD];
    size_t   len;
    time_t   queued_at;
    uint8_t  type;
    bool     used;
} pending_msg_t;

typedef struct {
    overlay_sess_state_t state;
    int                  utp_conn_id;
    uint8_t              peer_id[OVERLAY_PEER_ID_LEN];
    bool                 peer_id_valid;
    bool                 crypto_ready;
    uint8_t              session_key[32];
    uint64_t             tx_nonce;
    uint64_t             rx_last_nonce;
    bool                 rx_nonce_valid;
    bool                 is_outbound;
    struct sockaddr_in   peer_addr;
    time_t               last_activity;

    uint8_t  rbuf[5 + OVERLAY_CHUNK_MAX + OVERLAY_RESP_HDR +
                  OVERLAY_CRYPTO_OVERHEAD + 64];
    size_t   rbuf_len;

    // stuff for handling brief disconnects
    int                  reconnect_attempts;
    time_t               reconnect_after;
    time_t               last_keepalive_sent;
    time_t               last_keepalive_recv;
    pending_msg_t        pending_queue[OVERLAY_PENDING_MSG_MAX];
    int                  pending_count;
    bool                 auto_reconnect;
} overlay_session_t;

// callbacks for upper layer

// called when overlay session finishes handshake
typedef void (*overlay_connected_cb_t)(int sess_id,
                                        const uint8_t peer_id[OVERLAY_PEER_ID_LEN]);

// called when we get a request (0x01) on sess_id
typedef void (*overlay_request_cb_t)(int sess_id,
                                      const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                                      uint32_t offset,
                                      uint32_t length);

// called when we get a response chunk (0x02)
typedef void (*overlay_response_cb_t)(int sess_id,
                                       const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                                       uint32_t offset,
                                       const uint8_t *data,
                                       size_t data_len);

// called when we get a pex message (0x03)
typedef void (*overlay_pex_cb_t)(int sess_id,
                                   const struct sockaddr_in *peers,
                                   const uint8_t (*node_ids)[OVERLAY_PEER_ID_LEN],
                                   int count);

// called when sess_id closes
typedef void (*overlay_closed_cb_t)(int sess_id);

// public api

// init overlay subsystem
// my_peer_id: 20 bytes of this node's identity
void overlay_init(const uint8_t my_peer_id[OVERLAY_PEER_ID_LEN]);

// register callbacks for session events
void overlay_set_callbacks(overlay_connected_cb_t on_connected,
                            overlay_request_cb_t   on_request,
                            overlay_response_cb_t  on_response,
                            overlay_pex_cb_t       on_pex,
                            overlay_closed_cb_t    on_closed);

// shut down overlay subsystem, closes all sessions
void overlay_shutdown(void);

// open overlay session to peer at peer_addr
// returns sess_id >= 0 or -1 if table is full
int overlay_connect(struct sockaddr_in peer_addr);

// close session sess_id
void overlay_close(int sess_id);

// send a request (0x01) to peer on sess_id
bool overlay_send_request(int sess_id,
                           const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                           uint32_t offset,
                           uint32_t length);

// send a response (0x02) to peer on sess_id
bool overlay_send_response(int sess_id,
                            const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                            uint32_t offset,
                            const uint8_t *data,
                            size_t data_len);

// send a pex message (0x03) to peer on sess_id
bool overlay_send_pex(int sess_id,
                       const struct sockaddr_in *peers,
                       const uint8_t (*node_ids)[OVERLAY_PEER_ID_LEN],
                       int count);

// call this from event loop when utp_data_cb_t fires
void overlay_on_data(int utp_conn_id);

// call when utp_accept_cb_t fires (incoming connection)
// creates overlay session and waits for peer handshake
void overlay_on_accept(int utp_conn_id, struct sockaddr_in peer);

// call when utp_close_cb_t fires
void overlay_on_close(int utp_conn_id);

// periodic timer, handles handshake/inactivity timeouts
// call this like once a second or so
void overlay_tick(void);

// returns sess_id for the given utp_conn_id, or -1 if not found
int overlay_find_by_utp(int utp_conn_id);

// returns number of established sessions right now
int overlay_session_count(void);

// dump state of all active sessions
void overlay_dump_sessions(void);

// force send keepalive to specific session
// returns true if sent ok
bool overlay_send_keepalive(int sess_id);

// set auto-reconnect for a session
void overlay_set_auto_reconnect(int sess_id, bool auto_reconnect);

// find session by peer_id. returns sess_id >= 0 or -1 if not found
int overlay_find_by_peer_id(const uint8_t peer_id[OVERLAY_PEER_ID_LEN]);

// GOSSIP→OVERLAY MIGRATION: find session by node_id_t from network
// auto-converts node_id_t → sockaddr_in
// returns sess_id >= 0 or -1 if not found
int overlay_find_by_net_id(node_id_t net_id);

// control command handlers via overlay instead of gossip
void overlay_on_control_request(int sess_id,
                               const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                               uint32_t offset,
                               uint32_t length);

void overlay_on_control_response(int sess_id,
                                const uint8_t infohash[OVERLAY_INFOHASH_LEN],
                                uint32_t offset,
                                const uint8_t *data,
                                size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* P2P_OVERLAY_H */
