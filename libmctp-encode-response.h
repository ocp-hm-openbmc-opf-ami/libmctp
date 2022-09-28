/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_ENCODE_RESPONSE_H
#define _LIBMCTP_ENCODE_RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

encode_decode_api_return_code
mctp_encode_resolve_eid_resp(struct mctp_msg *response, size_t length,
			     uint8_t rq_dgram_inst, uint8_t bridge_eid,
			     struct variable_field *address);

encode_decode_api_return_code
mctp_encode_allocate_endpoint_id_resp(struct mctp_msg *response, size_t length,
				      struct mctp_ctrl_msg_hdr *ctrl_hdr,
				      mctp_ctrl_cmd_allocate_eids_resp_op op,
				      uint8_t eid_pool_size, uint8_t first_eid);

encode_decode_api_return_code
mctp_encode_set_eid_resp(struct mctp_msg *response, size_t length,
			 struct mctp_ctrl_msg_hdr *ctrl_hdr,
			 uint8_t eid_pool_size, uint8_t status,
			 mctp_eid_t eid_set);

encode_decode_api_return_code
mctp_encode_get_uuid_resp(struct mctp_msg *response, size_t length,
			  struct mctp_ctrl_msg_hdr *ctrl_hdr,
			  const guid_t *uuid);

encode_decode_api_return_code
mctp_encode_get_networkid_resp(struct mctp_msg *response, size_t length,
			       guid_t *networkid);

encode_decode_api_return_code mctp_encode_get_routing_table_resp(
	struct mctp_msg *response, size_t length,
	struct get_routing_table_entry_with_address *entries,
	uint8_t no_of_entries, size_t *resp_size,
	const uint8_t next_entry_handle);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ENCODE_RESPONSE_H */
