/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_H
#define _LIBMCTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef uint8_t mctp_eid_t;

/* Special Endpoint ID values */
#define MCTP_EID_NULL 0
#define MCTP_EID_BROADCAST 0xff

/* MCTP packet definitions */
struct mctp_hdr {
	uint8_t ver;
	uint8_t dest;
	uint8_t src;
	uint8_t flags_seq_tag;
};

/* Definitions for flags_seq_tag field */
#define MCTP_HDR_FLAG_SOM (1 << 7)
#define MCTP_HDR_FLAG_EOM (1 << 6)
#define MCTP_HDR_FLAG_TO (1 << 3)
#define MCTP_HDR_VER_SHIFT 0
#define MCTP_HDR_VER_MASK 0xf
#define MCTP_HDR_SET_VER(field, ver)                                           \
	((field) |= (((ver)&MCTP_HDR_VER_MASK) << MCTP_HDR_VER_SHIFT))
#define MCTP_HDR_GET_VER(field)                                                \
	(((field) >> MCTP_HDR_VER_SHIFT) & MCTP_HDR_VER_MASK)
#define MCTP_HDR_SEQ_SHIFT 4
#define MCTP_HDR_SEQ_MASK 0x3
#define MCTP_HDR_SET_SEQ(field, seq)                                           \
	((field) |= (((seq)&MCTP_HDR_SEQ_MASK) << MCTP_HDR_SEQ_SHIFT))
#define MCTP_HDR_GET_SEQ(field)                                                \
	(((field) >> MCTP_HDR_SEQ_SHIFT) & MCTP_HDR_SEQ_MASK)
#define MCTP_HDR_TAG_SHIFT 0
#define MCTP_HDR_TAG_MASK 0x7
#define MCTP_HDR_SET_TAG(field, tag)                                           \
	((field) |= (((tag)&MCTP_HDR_TAG_MASK) << MCTP_HDR_TAG_SHIFT))
#define MCTP_HDR_GET_TAG(field)                                                \
	(((field) >> MCTP_HDR_TAG_SHIFT) & MCTP_HDR_TAG_MASK)

/* Baseline Transmission Unit and packet size */
#define MCTP_BTU 64
#define MCTP_PACKET_SIZE(unit) ((unit) + sizeof(struct mctp_hdr))

#define TX_DISABLED_ERR (-1024)

#define ENDPOINT_TYPE_SIMPLE_ENDPOINT 0
#define ENDPOINT_TYPE_BUS_OWNER_BRIDGE 1
#define ENDPOINT_TYPE_SHIFT 4

struct mctp_binding;
/* packet buffers */

struct mctp_pktbuf {
	size_t start, end, size;
	size_t mctp_hdr_off;
	struct mctp_pktbuf *next;
	/* binding private data */
	void *msg_binding_private;
	uint8_t data[];
};

struct mctp_pktbuf *mctp_pktbuf_alloc(struct mctp_binding *hw, size_t len);
void mctp_pktbuf_free(struct mctp_pktbuf *pkt);
struct mctp_hdr *mctp_pktbuf_hdr(struct mctp_pktbuf *pkt);
void *mctp_pktbuf_data(struct mctp_pktbuf *pkt);
uint8_t mctp_pktbuf_size(struct mctp_pktbuf *pkt);
uint8_t mctp_pktbuf_end_index(struct mctp_pktbuf *pkt);
void *mctp_pktbuf_alloc_start(struct mctp_pktbuf *pkt, size_t size);
void *mctp_pktbuf_alloc_end(struct mctp_pktbuf *pkt, size_t size);
int mctp_pktbuf_push(struct mctp_pktbuf *pkt, void *data, size_t len);

/* MCTP core */
struct mctp;
struct mctp_bus;

struct mctp *mctp_init(void);
void mctp_set_max_message_size(struct mctp *mctp, size_t message_size);
void mctp_destroy(struct mctp *mctp);
bool is_eid_valid(mctp_eid_t eid);

/* Register a binding to the MCTP core, and creates a bus (populating
 * binding->bus).
 *
 * If this function is called, the MCTP stack is initialised as an 'endpoint',
 * and will deliver local packets to a RX callback - see `mctp_set_rx_all()`
 * below.
 */
int mctp_register_bus(struct mctp *mctp, struct mctp_binding *binding,
		      mctp_eid_t eid);

int mctp_register_bus_dynamic_eid(struct mctp *mctp,
				  struct mctp_binding *binding);

/* Sets eid for endpoints registered with mctp_register_bus_dynamic_eid()
 *
 * For applications that do not implement MCTP control protocol this function
 * shall be used immediately after endpoint is discovered to set up currently
 * assigned eid. This will make mctp_bus_rx() recognize endpoint's packets.
 */
int mctp_dynamic_eid_set(struct mctp_binding *binding, mctp_eid_t eid);

/* Create a simple bidirectional bridge between busses.
 *
 * In this mode, the MCTP stack is initialised as a bridge. There is no EID
 * defined, so no packets are considered local. Instead, all messages from one
 * binding are forwarded to the other.
 */
int mctp_bridge_busses(struct mctp *mctp, struct mctp_binding *b1,
		       struct mctp_binding *b2);

typedef void (*mctp_rx_fn)(uint8_t src_eid, void *data, void *msg, size_t len,
			   bool tag_owner, uint8_t tag,
			   void *msg_binding_private);

/* MCTP receive callback with headers also included in payload. */
typedef void (*mctp_raw_rx_cb)(void *data, void *msg, size_t len,
			       void *msg_binding_private);

int mctp_set_rx_all(struct mctp *mctp, mctp_rx_fn fn, void *data);
int mctp_set_rx_raw(struct mctp *mctp, mctp_raw_rx_cb fn);

/* Format MCTP packet from arguments and send. This will include adding headers
 * and assmebling if needed.
 */
int mctp_message_tx(struct mctp *mctp, mctp_eid_t eid, void *msg, size_t len,
		    bool tag_owner, uint8_t tag, void *msg_binding_private);
/* Transmit raw MCTP packet bytes including MCTP headers. Destination EID will
 * be taken from mctp header.
 */
int mctp_message_raw_tx(struct mctp *mctp, const void *msg, size_t len,
			void *msg_binding_private);

/* hardware bindings */
struct mctp_binding {
	const char *name;
	uint8_t version;
	struct mctp_bus *bus;
	struct mctp *mctp;
	size_t pkt_size;
	size_t pkt_pad;
	size_t pkt_priv_size;
	int (*start)(struct mctp_binding *binding);
	int (*tx)(struct mctp_binding *binding, struct mctp_pktbuf *pkt);
	mctp_rx_fn control_rx;
	void *control_rx_data;
	uint8_t info;
};

void mctp_binding_set_tx_enabled(struct mctp_binding *binding, bool enable);

/*
 * Receive a packet from binding to core. Takes ownership of pkt, free()-ing it
 * after use.
 */
void mctp_bus_rx(struct mctp_binding *binding, struct mctp_pktbuf *pkt);

/* environment-specific allocation */
void mctp_set_alloc_ops(void *(*alloc)(size_t), void (*free)(void *),
			void *(realloc)(void *, size_t));

/* environment-specific logging */

void mctp_set_log_stdio(int level);
void mctp_set_log_syslog(void);
void mctp_set_log_custom(void (*fn)(int, const char *, va_list));
void mctp_set_tracing_enabled(bool enable);

/* these should match the syslog-standard LOG_* definitions, for
 * easier use with syslog */
#define MCTP_LOG_ERR 3
#define MCTP_LOG_WARNING 4
#define MCTP_LOG_NOTICE 5
#define MCTP_LOG_INFO 6
#define MCTP_LOG_DEBUG 7

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_H */
