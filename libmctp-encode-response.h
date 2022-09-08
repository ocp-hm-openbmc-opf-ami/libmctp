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

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ENCODE_RESPONSE_H */
