/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_ENCODE_RESPONSE_H
#define _LIBMCTP_ENCODE_RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Encode function for response structure
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[in] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header structure
 *				definition: {uint8_t ic_msg_type;uint8_t
 *				rq_dgram_inst; uint8_t command_code;}
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] bridge_eid - Bridge eid field of response structure for  resolve
 *				eid command
 *  @param[in] address - Physical address field of response structure for
 *				resolve eid command
 *  @return encode enum type which tells error or success
 */
encode_decode_rc mctp_encode_resolve_eid_resp(struct mctp_msg *response,
					      size_t *length,
					      uint8_t rq_dgram_inst,
					      uint8_t completion_code,
					      uint8_t bridge_eid,
					      struct variable_field *address);

/** @brief Encode function for response structure
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[in] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header structure
 *				definition: {uint8_t ic_msg_type;uint8_t
 *				rq_dgram_inst; uint8_t command_code;}
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] op - operation field of response structure for  allocate eid
 *				command
 *  @param[in] eid_pool_size - eid pool size field of response structure for
 *				allocate eid command
 *  @param[in] first_eid - first eid field of response structure for  allocate
 *				eid command
 *  @return encode enum type which tells error or success
 */
encode_decode_rc mctp_encode_allocate_endpoint_id_resp(
	struct mctp_msg *response, size_t *length, uint8_t rq_dgram_inst,
	mctp_ctrl_cmd_allocate_eids_resp_op op, uint8_t completion_code,
	uint8_t eid_pool_size, uint8_t first_eid);

/** @brief Encode function for response structure
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[in] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure
 *			   definition: {uint8_t ic_msg_type;uint8_t
 *				rq_dgram_inst; uint8_t command_code;}
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] eid_pool_size - eid pool size field of response structure for set
 *				eid command
 *  @param[in] status - status field of response structure for  set eid command
 *  @param[in] eid_set - eid setting field of response structure for  set eid
 *				command
 *  @return encode enum type which tells error or success
 */
encode_decode_rc mctp_encode_set_eid_resp(struct mctp_msg *response,
					  size_t *length, uint8_t rq_dgram_inst,
					  uint8_t completion_code,
					  uint8_t eid_pool_size, uint8_t status,
					  mctp_eid_t eid_set);

/** @brief Encode function for response structure
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[in] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure
 *			   definition: {uint8_t ic_msg_type;uint8_t
 *				rq_dgram_inst; uint8_t command_code;}
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] uuid - UUID field of response structure for  get uuid command
 *  @return encode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_uuid_resp(struct mctp_msg *response,
					   size_t *length,
					   uint8_t rq_dgram_inst,
					   uint8_t completion_code,
					   const guid_t *uuid);

/** @brief Encode function for get networkid response
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[inout] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] network_id - network_id field of response structure for
 * 				get_networkid command
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_networkid_resp(struct mctp_msg *response,
						size_t *length,
						uint8_t completion_code,
						guid_t *network_id);

/** @brief Encode function for get routing table response
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[inout] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] entries - entries field of response structure for
 * 				get_routing_table command
 *  @param[in] no_of_entries - no_of_entries field of response structure for
 * 				get_routing_table command
 *  @param[in] next_entry_handle - next_entry_handle of response structure for
 * 				get_routing_table command
 *  @param[out] resp_size - resp_size of response structure
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_routing_table_resp(
	struct mctp_msg *response, size_t *length, uint8_t completion_code,
	struct get_routing_table_entry_with_address *entries,
	uint8_t no_of_entries, const uint8_t next_entry_handle,
	size_t *resp_size);

/** @brief Encode function for get version support response
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[inout] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] number_of_entries - number_of_entries field of response structure
 * 				for  get_ver_support command
 *  @param[in] vers - vers field of response structure for  get_ver_support
 * 				command
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_ver_support_resp(struct mctp_msg *request,
						  size_t *length,
						  uint8_t rq_dgram_inst,
						  uint8_t completion_code,
						  uint8_t number_of_entries,
						  struct version_entry *vers);

/** @brief Encode function for get eid response
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[inout] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] eid - eid field of response structure for  get_eid command
 *  @param[in] eid_type - eid_type field of response structure for  get_eid
 * 				command
 *  @param[in] medium_data - medium_data field of response structure for get_eid
 * 				command
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_eid_resp(struct mctp_msg *response,
					  size_t *length, uint8_t rq_dgram_inst,
					  uint8_t completion_code,
					  mctp_eid_t eid, uint8_t eid_type,
					  uint8_t medium_data);

/** @brief Encode function for get VDM support response
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[inout] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] vendor_id_set_selector - vendor_id_set_selector field of response
 * 				structure for getVDM support command
 *  @param[in] vendor_id_format - vendor_id_format field of response structure
 * 				for getVDM support command
 *  @param[in] vendor_id_data - vendor_id_data field of response structure with
 * 				structure type named variable_field for getVDM
 *				support command
 *  @param[in] cmd_set_type - cmd_set_type field of response structure for
 * 				getVDM support command
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_vdm_support_resp(
	struct mctp_msg *response, size_t *length, uint8_t rq_dgram_inst,
	uint8_t completion_code, uint8_t vendor_id_set_selector,
	uint8_t vendor_id_format, const struct variable_field *vendor_id_data,
	uint16_t cmd_set_type);

/** @brief Encode function for prepare endpoint discovery response
 *
 *  @param[out] response - Response structure to be encoded
 *  @param[inout] length - Length of response structure
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure
 *  @param[in] completion_code - completion code for response structure
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_prepare_endpoint_discovery_resp(
	struct mctp_msg *response, size_t *length, uint8_t rq_dgram_inst,
	uint8_t completion_code);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ENCODE_RESPONSE_H */
