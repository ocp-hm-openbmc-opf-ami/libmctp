/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_DECODE_RESPONSE_H
#define _LIBMCTP_DECODE_RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Decode function for request structure
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] resp_size - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure
 *			   definition: {uint8_t ic_msg_type;uint8_t
 *				rq_dgram_inst; uint8_t command_code;}
 *  @param[out] completion_code - completion code for response structure
 *  @param[out] bridge_eid - bridge eid of response for resolve eid command
 *  @param[out] address - Physical address field of response structure for
 *			  resolve eid command
 *  @return decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_resolve_eid_resp(
	const struct mctp_msg *response, const size_t resp_size,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *completion_code,
	uint8_t *bridge_eid, struct variable_field *address);

/** @brief Decode function for request structure
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] length - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure
 *			   definition: {uint8_t ic_msg_type;uint8_t
 *				rq_dgram_inst; uint8_t command_code;}
 *  @param[out] cc - completion code for response structure
 *  @param[out] op - operation field of response for allocate eid command
 *  @param[out] eid_pool_size - eid_pool_size field of response structure for
 *			  allocate eid command
 *  @param[out] first_eid - first_eid of response for allocate eid command
 *  @return decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_allocate_endpoint_id_resp(
	const struct mctp_msg *response, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *cc,
	mctp_ctrl_cmd_allocate_eids_resp_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid);

/** @brief Decode function for request structure
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] length - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure
 *			   definition: {uint8_t ic_msg_type;uint8_t
 *				rq_dgram_inst; uint8_t command_code;}
 *  @param[out] completion_code - completion code for response structure
 *  @param[out] eid_pool_size - EID Pool Size field of response for set eid
 *				command
 *  @param[out] status - status field of response structure for
 *			  	set eid command
 *  @param[out] eid_set - EID Setting field of response for set eid command
 *  @return decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_set_eid_resp(const struct mctp_msg *response,
					  const size_t length,
					  struct mctp_ctrl_msg_hdr *ctrl_hdr,
					  uint8_t *completion_code,
					  uint8_t *eid_pool_size,
					  uint8_t *status, mctp_eid_t *eid_set);

/** @brief Decode function for request structure
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] length - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure
 *			   definition: {uint8_t ic_msg_type;uint8_t
 *				rq_dgram_inst; uint8_t command_code;}
 *  @param[out] completion_code - completion code for response structure
 *  @param[out] uuid - UUID field of response for set get uuid command
 *  @return decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_get_uuid_resp(const struct mctp_msg *response,
					   const size_t length,
					   struct mctp_ctrl_msg_hdr *ctrl_hdr,
					   uint8_t *completion_code,
					   guid_t *uuid);

/** @brief Decode function for get networkid response
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] length - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure
 *  @param[out] completion_code - completion code for response structure
 *  @param[out] network_id - network_id field of response for get_networkid
 * 				command
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc
mctp_decode_get_networkid_resp(const struct mctp_msg *response,
			       const size_t length,
			       struct mctp_ctrl_msg_hdr *ctrl_hdr,
			       uint8_t *completion_code, guid_t *network_id);

/** @brief Decode function for get version support response
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] length - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure
 *  @param[out] completion_code - completion code for response structure
 *  @param[out] number_of_entries - number_of_entries field of response for
 *				    get_ver_support command
 *  @param[out] vers - array to hold parsed version_entry values
 *				from the response
 *  @param[in] verslen - capacity of vers array
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_get_ver_support_resp(
	const struct mctp_msg *response, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *completion_code,
	uint8_t *number_of_entries, struct version_entry *vers,
	const size_t verslen);

/** @brief Decode function for get eid response
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] length - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure
 *  @param[out] completion_code - completion code for response structure
 *  @param[out] eid - eid field of response for get_eid command
 *  @param[out] eid_type - eid type field of response for get_eid command
 *  @param[out] medium_data - medium_data field of response for get_eid command
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_get_eid_resp(const struct mctp_msg *response,
					  const size_t length,
					  struct mctp_ctrl_msg_hdr *ctrl_hdr,
					  uint8_t *completion_code,
					  mctp_eid_t *eid, uint8_t *eid_type,
					  uint8_t *medium_data);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_DECODE_RESPONSE_H */
