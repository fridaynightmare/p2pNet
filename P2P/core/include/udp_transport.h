// udp_transport.h - bounded reliable UDP transport for the P2P overlay

#ifndef UDP_TRANSPORT_H
#define UDP_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

// Callback function types
typedef void (*udp_on_connect_cb_t)(int conn_id);
typedef void (*udp_on_data_cb_t)(int conn_id, const uint8_t *data, size_t len);
typedef void (*udp_on_close_cb_t)(int conn_id);

// Register callbacks used by incoming connections and as defaults for
// outgoing connections that do not provide per-connection callbacks.
void udp_transport_set_callbacks(udp_on_connect_cb_t on_connect,
                                 udp_on_data_cb_t on_data,
                                 udp_on_close_cb_t on_close);

// Initialize UDP transport
// Returns 0 on success, -1 on error
int udp_transport_init(int local_port);

// Shutdown UDP transport
void udp_transport_shutdown(void);

// Connect to a peer
// Returns connection ID on success, -1 on error
int udp_transport_connect(const struct sockaddr_in *peer_addr,
                         udp_on_connect_cb_t on_connect,
                         udp_on_data_cb_t on_data,
                         udp_on_close_cb_t on_close);

// Send data to a connection
// Returns number of bytes sent, -1 on error
ssize_t udp_transport_write(int conn_id, const uint8_t *data, size_t len);

// Close a connection
void udp_transport_close(int conn_id);

// Process incoming packets and handle timeouts
// Call this regularly from main loop
void udp_transport_tick(void);

// Get last error message
const char* udp_transport_last_error(void);

// Get connection description for debugging
void udp_transport_describe_connection(int conn_id, char *buf, size_t buf_size);

// Copy the remote endpoint of an active connection.
int udp_transport_get_peer_addr(int conn_id, struct sockaddr_in *out);

// Dump statistics for debugging
void udp_transport_dump_stats(void);

#ifdef __cplusplus
}
#endif

#endif // UDP_TRANSPORT_H
