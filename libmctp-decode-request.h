/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_DECODE_REQUEST_H
#define _LIBMCTP_DECODE_REQUEST_H

#ifdef __cplusplus
extern "C" {
#endif

decode_rc mctp_decode_resolve_eid_req(const struct mctp_msg *request,
				      const size_t length,
				      struct mctp_ctrl_msg_hdr *ctrl_hdr,
				      uint8_t *target_eid);

decode_rc mctp_decode_allocate_endpoint_id_req(
	const struct mctp_msg *request, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr,
	mctp_ctrl_cmd_allocate_eids_req_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid);

decode_rc mctp_decode_set_eid_req(const struct mctp_msg *request,
				  const size_t length,
				  struct mctp_ctrl_msg_hdr *ctrl_hdr,
				  mctp_ctrl_cmd_set_eid_op *op, uint8_t *eid);

decode_rc mctp_decode_get_uuid_req(const struct mctp_msg *request,
				   const size_t length,
				   struct mctp_ctrl_msg_hdr *ctrl_hdr);

decode_rc mctp_decode_get_networkid_req(const struct mctp_msg *request,
					const size_t length,
					struct mctp_ctrl_msg_hdr *ctrl_hdr);

decode_rc mctp_decode_get_routing_table_req(const struct mctp_msg *request,
					    const size_t length,
					    struct mctp_ctrl_msg_hdr *ctrl_hdr,
					    uint8_t *entry_handle);

decode_rc mctp_decode_get_ver_support_req(const struct mctp_msg *request,
					  const size_t length,
					  struct mctp_ctrl_msg_hdr *ctrl_hdr,
					  uint8_t *msg_type_number);

decode_rc mctp_decode_get_eid_req(const struct mctp_msg *request,
				  const size_t length,
				  struct mctp_ctrl_msg_hdr *ctrl_hdr);

decode_rc mctp_decode_prepare_discovery_req(const struct mctp_msg *request,
					    const size_t length,
					    struct mctp_ctrl_msg_hdr *ctrl_hdr);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_DECODE_REQUEST_H */