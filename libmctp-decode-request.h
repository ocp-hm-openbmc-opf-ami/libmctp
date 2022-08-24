/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_DECODE_REQUEST_H
#define _LIBMCTP_DECODE_REQUEST_H

#ifdef __cplusplus
extern "C" {
#endif

encode_decode_api_return_code mctp_decode_resolve_eid_req(
	struct mctp_ctrl_cmd_resolve_eid_req *resolve_eid_cmd,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *target_eid);

encode_decode_api_return_code mctp_decode_allocate_endpoint_id_req(
	struct mctp_ctrl_cmd_allocate_eids_req *request, uint8_t *ic_msg_type,
	uint8_t *rq_dgram_inst, uint8_t *command_code,
	mctp_ctrl_cmd_allocate_eids_req_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_DECODE_REQUEST_H */