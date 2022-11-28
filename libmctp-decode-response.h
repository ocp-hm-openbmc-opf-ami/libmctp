/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_DECODE_RESPONSE_H
#define _LIBMCTP_DECODE_RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

decode_rc mctp_decode_resolve_eid_resp(const struct mctp_msg *response,
				       const size_t resp_size,
				       struct mctp_ctrl_msg_hdr *ctrl_hdr,
				       uint8_t *completion_code,
				       uint8_t *bridge_eid,
				       struct variable_field *address);

decode_rc mctp_decode_allocate_endpoint_id_resp(
	const struct mctp_msg *response, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *cc,
	mctp_ctrl_cmd_allocate_eids_resp_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid);

decode_rc mctp_decode_set_eid_resp(const struct mctp_msg *response,
				   const size_t length,
				   struct mctp_ctrl_msg_hdr *ctrl_hdr,
				   uint8_t *completion_code,
				   uint8_t *eid_pool_size, uint8_t *status,
				   mctp_eid_t *eid_set);

decode_rc mctp_decode_get_uuid_resp(const struct mctp_msg *response,
				    const size_t length,
				    struct mctp_ctrl_msg_hdr *ctrl_hdr,
				    uint8_t *completion_code, guid_t *uuid);

decode_rc mctp_decode_get_networkid_resp(const struct mctp_msg *response,
					 const size_t length,
					 struct mctp_ctrl_msg_hdr *ctrl_hdr,
					 uint8_t *completion_code,
					 guid_t *networkid);

decode_rc mctp_decode_get_ver_support_resp(const struct mctp_msg *response,
					   const size_t length,
					   struct mctp_ctrl_msg_hdr *ctrl_hdr,
					   uint8_t *completion_code,
					   uint8_t *number_of_entries);

decode_rc mctp_decode_get_eid_resp(const struct mctp_msg *response,
				   const size_t length,
				   struct mctp_ctrl_msg_hdr *ctrl_hdr,
				   uint8_t *completion_code, mctp_eid_t *eid,
				   uint8_t *eid_type, uint8_t *medium_data);

decode_rc mctp_decode_endpoint_discovery_resp(
	const struct mctp_msg *response, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *completion_code);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_DECODE_RESPONSE_H */