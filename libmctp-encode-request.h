/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_ENCODE_REQUEST_H
#define _LIBMCTP_ENCODE_REQUEST_H

#ifdef __cplusplus
extern "C" {
#endif

encode_decode_api_return_code
mctp_encode_resolve_eid_req(struct mctp_msg *request, const size_t length,
			    uint8_t rq_dgram_inst, uint8_t target_eid);

encode_decode_api_return_code
mctp_encode_allocate_endpoint_id_req(struct mctp_msg *request,
				     const size_t length, uint8_t rq_dgram_inst,
				     mctp_ctrl_cmd_allocate_eids_req_op op,
				     uint8_t pool_size, uint8_t starting_eid);

encode_decode_api_return_code
mctp_encode_set_eid_req(struct mctp_msg *request, const size_t length,
			uint8_t rq_dgram_inst, mctp_ctrl_cmd_set_eid_op op,
			uint8_t eid);

encode_decode_api_return_code mctp_encode_get_uuid_req(struct mctp_msg *request,
						       const size_t length,
						       uint8_t rq_dgram_inst);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ENCODE_REQUEST_H */