/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_ENCODE_RESPONSE_H
#define _LIBMCTP_ENCODE_RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

encode_rc mctp_encode_resolve_eid_resp(struct mctp_msg *response,
				       const size_t length,
				       uint8_t rq_dgram_inst,
				       uint8_t bridge_eid,
				       struct variable_field *address);

encode_rc mctp_encode_allocate_endpoint_id_resp(
	struct mctp_msg *response, const size_t length, uint8_t rq_dgram_inst,
	mctp_ctrl_cmd_allocate_eids_resp_op op, uint8_t eid_pool_size,
	uint8_t first_eid);

encode_rc mctp_encode_set_eid_resp(struct mctp_msg *response,
				   const size_t length, uint8_t rq_dgram_inst,
				   uint8_t eid_pool_size, uint8_t status,
				   mctp_eid_t eid_set);

encode_rc mctp_encode_get_uuid_resp(struct mctp_msg *response,
				    const size_t length, uint8_t rq_dgram_inst,
				    const guid_t *uuid);

encode_rc mctp_encode_get_networkid_resp(struct mctp_msg *response,
					 size_t length, guid_t *networkid);

encode_rc mctp_encode_get_routing_table_resp(
	struct mctp_msg *response, size_t length,
	struct get_routing_table_entry_with_address *entries,
	uint8_t no_of_entries, size_t *resp_size,
	const uint8_t next_entry_handle);

encode_rc mctp_encode_get_ver_support_resp(struct mctp_msg *request,
					   const size_t length,
					   uint8_t rq_dgram_inst,
					   uint8_t number_of_entries);

encode_rc mctp_encode_get_eid_resp(struct mctp_msg *response,
				   const size_t length, uint8_t rq_dgram_inst,
				   mctp_eid_t eid, uint8_t eid_type,
				   uint8_t medium_data);

encode_rc mctp_encode_get_vdm_support_resp(struct mctp_msg *response,
					   const size_t length,
					   uint8_t rq_dgram_inst,
					   uint8_t vendor_id_set_selector,
					   uint8_t vendor_id_format,
					   uint16_t vendor_id_data_pcie);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ENCODE_RESPONSE_H */
