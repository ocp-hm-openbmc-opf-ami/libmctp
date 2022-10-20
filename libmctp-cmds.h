/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_CMDS_H
#define _LIBMCTP_CMDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"

/*
 * Helper structs and functions for MCTP control messages.
 * See DSP0236 v1.3.0 sec. 11 for reference.
 */

struct mctp_ctrl_msg_hdr {
	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
} __attribute__((__packed__));

struct mctp_msg {
	struct mctp_ctrl_msg_hdr msg_hdr;
	uint8_t message_ptr[1];
} __attribute__((__packed__));

typedef enum {
	ENCODE_SUCCESS = 0,
	ENCODE_CC_ERROR,
	ENCODE_INPUT_ERROR,
	ENCODE_GENERIC_ERROR
} encode_rc;

typedef enum {
	DECODE_SUCCESS = 0,
	DECODE_CC_ERROR,
	DECODE_INPUT_ERROR,
	DECODE_GENERIC_ERROR
} decode_rc;

typedef union {
	struct {
		uint32_t data0;
		uint16_t data1;
		uint16_t data2;
		uint16_t data3;
		uint8_t data4[6];
	} __attribute__((__packed__)) canonical;
	uint8_t raw[16];
} guid_t;

typedef enum {
	set_eid,
	force_eid,
	reset_eid,
	set_discovered_flag
} mctp_ctrl_cmd_set_eid_op;

typedef enum {
	allocate_eids,
	force_allocation,
	get_allocation_info,
	reserved
} mctp_ctrl_cmd_allocate_eids_req_op;

typedef enum {
	allocation_accepted,
	allocation_rejected,
} mctp_ctrl_cmd_allocate_eids_resp_op;

struct mctp_ctrl_cmd_set_eid {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	mctp_ctrl_cmd_set_eid_op operation : 2;
	uint8_t : 6;
	uint8_t eid;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_allocate_eids_req {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	mctp_ctrl_cmd_allocate_eids_req_op operation : 2;
	uint8_t : 6;
	uint8_t eid_pool_size;
	uint8_t first_eid;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_eid {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_uuid {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_resolve_uuid_req {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	guid_t req_uuid;
	uint8_t entry_handle;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_networkid_req {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_mctp_ver_support {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t msg_type_number;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_msg_type_support {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_vdm_support {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t vendor_id_set_selector;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_discovery_notify {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_routing_table {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t entry_handle;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_resolve_eid_req {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t target_eid;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_query_hop_req {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t target_eid;
	uint8_t mctp_ctrl_msg_type;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_get_routing_table_req {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t entry_handle;
} __attribute__((__packed__));

#define MCTP_CTRL_HDR_MSG_TYPE 0
#define MCTP_CTRL_HDR_FLAG_REQUEST (1 << 7)
#define MCTP_CTRL_HDR_FLAG_DGRAM (1 << 6)
#define MCTP_CTRL_HDR_INSTANCE_ID_MASK 0x1F
#define MIN_RESP_LENGTH                                                        \
	(sizeof(struct mctp_ctrl_msg_hdr) + sizeof(MCTP_CTRL_CC_SUCCESS))

/*
 * MCTP Control Command IDs
 * See DSP0236 v1.3.0 Table 12.
 */
#define MCTP_CTRL_CMD_RESERVED 0x00
#define MCTP_CTRL_CMD_SET_ENDPOINT_ID 0x01
#define MCTP_CTRL_CMD_GET_ENDPOINT_ID 0x02
#define MCTP_CTRL_CMD_GET_ENDPOINT_UUID 0x03
#define MCTP_CTRL_CMD_GET_VERSION_SUPPORT 0x04
#define MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT 0x05
#define MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT 0x06
#define MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID 0x07
#define MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS 0x08
#define MCTP_CTRL_CMD_ROUTING_INFO_UPDATE 0x09
#define MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES 0x0A
#define MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY 0x0B
#define MCTP_CTRL_CMD_ENDPOINT_DISCOVERY 0x0C
#define MCTP_CTRL_CMD_DISCOVERY_NOTIFY 0x0D
#define MCTP_CTRL_CMD_GET_NETWORK_ID 0x0E
#define MCTP_CTRL_CMD_QUERY_HOP 0x0F
#define MCTP_CTRL_CMD_RESOLVE_UUID 0x10
#define MCTP_CTRL_CMD_QUERY_RATE_LIMIT 0x11
#define MCTP_CTRL_CMD_REQUEST_TX_RATE_LIMIT 0x12
#define MCTP_CTRL_CMD_UPDATE_RATE_LIMIT 0x13
#define MCTP_CTRL_CMD_QUERY_SUPPORTED_INTERFACES 0x14
#define MCTP_CTRL_CMD_MAX 0x15
/* 0xF0 - 0xFF are transport specific */
#define MCTP_CTRL_CMD_FIRST_TRANSPORT 0xF0
#define MCTP_CTRL_CMD_LAST_TRANSPORT 0xFF

/*
 * MCTP Control Completion Codes
 * See DSP0236 v1.3.0 Table 13.
 */
#define MCTP_CTRL_CC_SUCCESS 0x00
#define MCTP_CTRL_CC_ERROR 0x01
#define MCTP_CTRL_CC_ERROR_INVALID_DATA 0x02
#define MCTP_CTRL_CC_ERROR_INVALID_LENGTH 0x03
#define MCTP_CTRL_CC_ERROR_NOT_READY 0x04
#define MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD 0x05
/* 0x80 - 0xFF are command specific */

#define MCTP_CTRL_CC_GET_MCTP_VER_SUPPORT_UNSUPPORTED_TYPE 0x80

/* MCTP Set Endpoint ID response fields
 * See DSP0236 v1.3.0 Table 14.
 */

#define MCTP_EID_ASSIGNMENT_STATUS_SHIFT 0x4
#define MCTP_EID_ASSIGNMENT_STATUS_MASK 0x3
#define SET_MCTP_EID_ASSIGNMENT_STATUS(field, status)                          \
	((field) |= (((status)&MCTP_EID_ASSIGNMENT_STATUS_MASK)                \
		     << MCTP_EID_ASSIGNMENT_STATUS_SHIFT))
#define MCTP_SET_EID_ACCEPTED 0x0
#define MCTP_SET_EID_REJECTED 0x1

/* MCTP Physical Transport Binding identifiers
 * See DSP0239 v1.9.0 Table 3.
 */
#define MCTP_BINDING_RESERVED 0x00
#define MCTP_BINDING_SMBUS 0x01
#define MCTP_BINDING_PCIE 0x02
#define MCTP_BINDING_USB 0x03
#define MCTP_BINDING_KCS 0x04
#define MCTP_BINDING_SERIAL 0x05
#define MCTP_BINDING_I3C 0x06
#define MCTP_BINDING_VENDOR_DEFINED 0xFF

#define MCTP_GET_VDM_SUPPORT_PCIE_FORMAT_ID 0x00
#define MCTP_GET_VDM_SUPPORT_IANA_FORMAT_ID 0x01
#define MCTP_GET_VDM_SUPPORT_NO_MORE_CAP_SET 0xFF

#define MIN_RESP_LENGTH                                                        \
	(sizeof(struct mctp_ctrl_msg_hdr) + sizeof(MCTP_CTRL_CC_SUCCESS))

#define MCTP_ENDPOINT_TYPE_SHIFT 4
#define MCTP_ENDPOINT_TYPE_MASK 0x3
#define MCTP_SIMPLE_ENDPOINT 0
#define MCTP_BUS_OWNER_BRIDGE 1
#define SET_ENDPOINT_TYPE(field, type)                                         \
	((field) |=                                                            \
	 (((type)&MCTP_ENDPOINT_TYPE_MASK) << MCTP_ENDPOINT_TYPE_SHIFT))

#define MCTP_ENDPOINT_ID_TYPE_SHIFT 0
#define MCTP_ENDPOINT_ID_TYPE_MASK 0x3
#define MCTP_DYNAMIC_EID 0
#define MCTP_STATIC_EID 1
#define SET_ENDPOINT_ID_TYPE(field, type)                                      \
	((field) |=                                                            \
	 (((type)&MCTP_ENDPOINT_ID_TYPE_MASK) << MCTP_ENDPOINT_ID_TYPE_SHIFT))

/* MCTP Routing Table entry types
 * See DSP0236 v1.3.0 Table 27.
 */
#define MCTP_ROUTING_ENTRY_PORT_SHIFT 0
#define MCTP_ROUTING_ENTRY_PORT_MASK 0x1F
#define SET_ROUTING_ENTRY_PORT(field, port)                                    \
	((field) |= (((port)&MCTP_ROUTING_ENTRY_PORT_MASK)                     \
		     << MCTP_ROUTING_ENTRY_PORT_SHIFT))
#define GET_ROUTING_ENTRY_PORT(field)                                          \
	(((field) >> MCTP_ROUTING_ENTRY_PORT_SHIFT) &                          \
	 MCTP_ROUTING_ENTRY_PORT_MASK)

#define MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_SHIFT 5
#define MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_MASK 0x1
#define MCTP_DYNAMIC_ASSIGNMENT 0
#define MCTP_STATIC_ASSIGNMENT 1
#define SET_ROUTING_ENTRY_ASSIGNMENT_TYPE(field, type)                         \
	((field) |= (((type)&MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_MASK)          \
		     << MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_SHIFT))
#define GET_ROUTING_ENTRY_ASSIGNMENT_TYPE(field)                               \
	(((field) >> MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_SHIFT) &               \
	 MCTP_ROUTING_ENTRY_ASSIGNMENT_TYPE_MASK)

#define MCTP_ROUTING_ENTRY_TYPE_SHIFT 6
#define MCTP_ROUTING_ENTRY_TYPE_MASK 0x3
#define MCTP_ROUTING_ENTRY_ENDPOINT 0x00
#define MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS 0x01
#define MCTP_ROUTING_ENTRY_BRIDGE 0x02
#define MCTP_ROUTING_ENTRY_ENDPOINTS 0x03
#define SET_ROUTING_ENTRY_TYPE(field, type)                                    \
	((field) |= (((type)&MCTP_ROUTING_ENTRY_TYPE_MASK)                     \
		     << MCTP_ROUTING_ENTRY_TYPE_SHIFT))
#define GET_ROUTING_ENTRY_TYPE(field)                                          \
	(((field) >> MCTP_ROUTING_ENTRY_TYPE_SHIFT) &                          \
	 MCTP_ROUTING_ENTRY_TYPE_MASK)

#define MCTP_GET_VERSION_SUPPORT_BASE_INFO 0xFF

struct mctp_ctrl_resp_get_eid {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	mctp_eid_t eid;
	uint8_t eid_type;
	uint8_t medium_data;
} __attribute__((__packed__));

struct mctp_ctrl_resp_get_uuid {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	guid_t uuid;
} __attribute__((__packed__));

struct mctp_ctrl_resp_set_eid {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t status;
	mctp_eid_t eid_set;
	uint8_t eid_pool_size;
} __attribute__((__packed__));

struct mctp_ctrl_resp_discovery_notify {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
} __attribute__((__packed__));

struct mctp_ctrl_resp_prepare_discovery {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
} __attribute__((__packed__));

struct mctp_ctrl_resp_endpoint_discovery {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
} __attribute__((__packed__));

struct get_routing_table_entry {
	uint8_t eid_range_size;
	uint8_t starting_eid;
	uint8_t entry_type;
	uint8_t phys_transport_binding_id;
	uint8_t phys_media_type_id;
	uint8_t phys_address_size;
} __attribute__((__packed__));

struct mctp_ctrl_resp_routing_info_update {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_allocate_eids_resp {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	mctp_ctrl_cmd_allocate_eids_resp_op operation : 2;
	uint8_t : 6;
	uint8_t eid_pool_size;
	uint8_t first_eid;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_routing_info_update {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t count;
	uint8_t entries[0];
} __attribute__((__packed__));

struct routing_info_update_entry {
	uint8_t type;
	uint8_t eid_count;
	uint8_t starting_eid;
	uint8_t address[0];
} __attribute__((__packed__));

/* Assume 8 byte is enough for holding largest physical address */
#define MAX_PHYSICAL_ADDRESS_SIZE 8

struct get_routing_table_entry_with_address {
	struct get_routing_table_entry routing_info;
	uint8_t phys_address[MAX_PHYSICAL_ADDRESS_SIZE];
} __attribute__((__packed__));

struct mctp_ctrl_resp_get_routing_table {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t next_entry_handle;
	uint8_t number_of_entries;
	struct get_routing_table_entry_with_address entries[0];
} __attribute__((__packed__));

struct mctp_ctrl_resp_get_vdm_support {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t vendor_id_set_selector;
	uint8_t vendor_id_format;
	union {
		uint16_t vendor_id_data_pcie;
		uint32_t vendor_id_data_iana;
	};
	/* following bytes are dependent on vendor id format
	 * and shall be interpreted by appropriate binding handler */
} __attribute__((__packed__));

struct mctp_pci_ctrl_resp_get_vdm_support {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t vendor_id_set_selector;
	uint8_t vendor_id_format;
	uint16_t vendor_id_data;
	uint16_t command_set_type;
} __attribute__((__packed__));

struct mctp_ctrl_resp_get_msg_type_support {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t msg_type_count;
} __attribute__((__packed__));

struct msg_type_entry {
	uint8_t msg_type_no;
} __attribute__((__packed__));

struct mctp_ctrl_resp_get_mctp_ver_support {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t number_of_entries;
} __attribute__((__packed__));

struct mctp_ctrl_resp_completion_code {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
} __attribute__((__packed__));

struct version_entry {
	uint8_t major;
	uint8_t minor;
	uint8_t update;
	uint8_t alpha;
} __attribute__((__packed__));

struct mctp_ctrl_get_networkid_resp {
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	guid_t networkid;
} __attribute__((__packed__));

struct variable_field {
	uint8_t *data;
	size_t data_size;
} __attribute__((__packed__));

struct mctp_ctrl_cmd_resolve_eid_resp {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t completion_code;
	uint8_t bridge_eid;
	uint8_t physical_address[0];
} __attribute__((__packed__));

struct mctp_ctrl_cmd_query_hop_resp {
	struct mctp_ctrl_msg_hdr ctrl_msg_hdr;
	uint8_t completion_code;
	uint8_t next_bridge_eid;
	uint8_t mctp_ctrl_msg_type;
	uint16_t max_incoming_size;
	uint16_t max_outgoing_size;
} __attribute__((__packed__));

bool mctp_ctrl_handle_msg(struct mctp *mctp, struct mctp_bus *bus,
			  mctp_eid_t src, mctp_eid_t dest, void *buffer,
			  size_t length, bool tag_owner, uint8_t tag,
			  void *msg_binding_private);

int mctp_set_rx_ctrl(struct mctp *mctp, mctp_rx_fn fn, void *data);

bool mctp_encode_ctrl_cmd_set_eid(struct mctp_ctrl_cmd_set_eid *set_eid_cmd,
				  uint8_t rq_dgram_inst,
				  mctp_ctrl_cmd_set_eid_op op, uint8_t eid);

bool mctp_encode_ctrl_cmd_get_eid(struct mctp_ctrl_cmd_get_eid *get_eid_cmd,
				  uint8_t rq_dgram_inst);

bool mctp_encode_ctrl_cmd_get_uuid(struct mctp_ctrl_cmd_get_uuid *get_uuid_cmd,
				   uint8_t rq_dgram_inst);

bool mctp_encode_ctrl_cmd_resolve_uuid_req(
	struct mctp_ctrl_cmd_resolve_uuid_req *res_uuid_cmd,
	uint8_t rq_dgram_inst, guid_t *req_uuid, uint8_t handle);

bool mctp_encode_ctrl_cmd_get_networkid_req(
	struct mctp_ctrl_cmd_get_networkid_req *get_networkid_cmd,
	uint8_t rq_dgram_inst);

bool mctp_decode_ctrl_cmd_network_id_req(void *request, size_t request_size,
					 struct mctp_ctrl_msg_hdr *hdr);

bool mctp_decode_ctrl_cmd_network_id_resp(void *response, size_t response_size,
					  struct mctp_ctrl_msg_hdr *hdr,
					  uint8_t *completion_code,
					  guid_t *networkid);

bool mctp_encode_ctrl_cmd_get_ver_support(
	struct mctp_ctrl_cmd_get_mctp_ver_support *mctp_ver_support_cmd,
	uint8_t rq_dgram_inst, uint8_t msg_type_number);

bool mctp_encode_ctrl_cmd_get_msg_type_support(
	struct mctp_ctrl_cmd_get_msg_type_support *msg_type_support_cmd,
	uint8_t rq_dgram_inst);

bool mctp_encode_ctrl_cmd_get_vdm_support(
	struct mctp_ctrl_cmd_get_vdm_support *vdm_support_cmd,
	uint8_t rq_dgram_inst, uint8_t v_id_set_selector);

bool mctp_encode_ctrl_cmd_discovery_notify(
	struct mctp_ctrl_cmd_discovery_notify *discovery_notify_cmd,
	uint8_t rq_dgram_inst);

bool mctp_encode_ctrl_cmd_get_routing_table(
	struct mctp_ctrl_cmd_get_routing_table *get_routing_table_cmd,
	uint8_t rq_dgram_inst, uint8_t entry_handle);

bool mctp_encode_ctrl_cmd_routing_information_update(
	struct mctp_ctrl_cmd_routing_info_update *routing_info_update_cmd,
	uint8_t rq_dgram_inst,
	struct get_routing_table_entry_with_address *entries,
	uint8_t no_of_entries, size_t *new_req_size);

bool mctp_encode_ctrl_cmd_resolve_eid_req(
	struct mctp_ctrl_cmd_resolve_eid_req *resolve_eid_cmd,
	uint8_t rq_dgram_inst, uint8_t target_eid);

bool mctp_encode_ctrl_cmd_get_routing_table_resp(
	struct mctp_ctrl_resp_get_routing_table *resp,
	struct get_routing_table_entry_with_address *entries,
	uint8_t no_of_entries, size_t *resp_size,
	const uint8_t next_entry_handle);

bool mctp_encode_ctrl_cmd_query_hop_req(
	struct mctp_ctrl_cmd_query_hop_req *query_hop_cmd,
	uint8_t rq_dgram_inst, const uint8_t eid,
	const uint8_t mctp_ctrl_msg_type);

void mctp_set_uuid(struct mctp *mctp, guid_t uuid);

bool mctp_is_mctp_ctrl_msg(void *buf, size_t len);

bool mctp_ctrl_msg_is_req(void *buf, size_t len);

int mctp_ctrl_cmd_set_endpoint_id(struct mctp *mctp, mctp_eid_t dest_eid,
				  struct mctp_ctrl_cmd_set_eid *request,
				  struct mctp_ctrl_resp_set_eid *response);

int mctp_ctrl_cmd_get_endpoint_id(struct mctp *mctp, mctp_eid_t dest_eid,
				  bool bus_owner,
				  struct mctp_ctrl_resp_get_eid *response);

int mctp_ctrl_cmd_get_vdm_support(
	struct mctp *mctp, mctp_eid_t src_eid,
	struct mctp_ctrl_resp_get_vdm_support *response);

bool mctp_encode_ctrl_cmd_resolve_eid_resp(
	struct mctp_ctrl_cmd_resolve_eid_resp *response, uint8_t rq_dgram_inst,
	uint8_t bridge_eid, struct variable_field *address);

bool encode_cc_only_response(uint8_t cc,
			     struct mctp_ctrl_resp_completion_code *response);

/*Allocate EID encode and decode APIs*/
bool mctp_encode_ctrl_cmd_allocate_endpoint_id_req(
	struct mctp_ctrl_cmd_allocate_eids_req *set_eid_cmd,
	uint8_t rq_dgram_inst, mctp_ctrl_cmd_allocate_eids_req_op op,
	uint8_t pool_size, uint8_t starting_eid);

bool mctp_encode_ctrl_cmd_allocate_endpoint_id_resp(
	struct mctp_ctrl_cmd_allocate_eids_resp *response,
	struct mctp_ctrl_msg_hdr *ctrl_hdr,
	mctp_ctrl_cmd_allocate_eids_resp_op op, uint8_t eid_pool_size,
	uint8_t first_eid);

bool mctp_decode_ctrl_cmd_allocate_endpoint_id_req(
	struct mctp_ctrl_cmd_allocate_eids_req *request, uint8_t *ic_msg_type,
	uint8_t *rq_dgram_inst, uint8_t *command_code,
	mctp_ctrl_cmd_allocate_eids_req_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid);

bool mctp_decode_ctrl_cmd_allocate_endpoint_id_resp(
	struct mctp_ctrl_cmd_allocate_eids_resp *response, uint8_t *ic_msg_type,
	uint8_t *rq_dgram_inst, uint8_t *command_code, uint8_t *cc,
	mctp_ctrl_cmd_allocate_eids_resp_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid);
bool mctp_encode_ctrl_cmd_get_uuid_resp(struct mctp_ctrl_resp_get_uuid *response,
					struct mctp_ctrl_msg_hdr *ctrl_hdr,
					const guid_t *uuid);

bool mctp_set_networkid(struct mctp *mctp, guid_t *network_id);

bool mctp_get_networkid(struct mctp *mctp, guid_t *network_id);

bool mctp_encode_ctrl_cmd_get_network_id_resp(
	struct mctp_ctrl_get_networkid_resp *response, guid_t *networkid);

bool mctp_decode_ctrl_cmd_resolve_eid_req(
	struct mctp_ctrl_cmd_resolve_eid_req *resolve_eid_cmd,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *target_eid);

bool mctp_decode_ctrl_cmd_resolve_eid_resp(
	struct mctp_ctrl_cmd_resolve_eid_resp *response, size_t resp_size,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *completion_code,
	uint8_t *bridge_eid, struct variable_field *address);

bool mctp_decode_ctrl_cmd_get_query_hop_resp(
	const void *response, size_t resp_size, struct mctp_ctrl_msg_hdr *hdr,
	uint8_t *completion_code, uint8_t *next_bridge_eid,
	uint8_t *mctp_ctrl_msg_type, uint16_t *max_incoming_size,
	uint16_t *max_outgoing_size);

bool mctp_decode_ctrl_cmd_query_hop_req(const void *request, size_t req_size,
					struct mctp_ctrl_msg_hdr *hdr,
					uint8_t *eid,
					uint8_t *mctp_ctrl_msg_type);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_CMDS_H */
