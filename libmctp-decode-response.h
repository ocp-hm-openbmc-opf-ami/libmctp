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
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[out] completion_code - completion code for response structure
 *  @param[out] bridge_eid - bridge eid of response for resolve eid command
 *  @param[out] address - Physical address field of response structure for
 *			  resolve eid command
 *  @return decode enum type which tells error or success
 */
decode_rc mctp_decode_resolve_eid_resp(const struct mctp_msg *response,
				       const size_t resp_size,
				       struct mctp_ctrl_msg_hdr *ctrl_hdr,
				       uint8_t *completion_code,
				       uint8_t *bridge_eid,
				       struct variable_field *address);

/** @brief Decode function for request structure
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] length - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[out] cc - completion code for response structure
 *  @param[out] op - operation field of response for allocate eid command
 *  @param[out] eid_pool_size - eid_pool_size field of response structure for
 *			  allocate eid command
 *  @param[out] first_eid - first_eid of response for allocate eid command
 *  @return decode enum type which tells error or success
 */
decode_rc mctp_decode_allocate_endpoint_id_resp(
	const struct mctp_msg *response, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *cc,
	mctp_ctrl_cmd_allocate_eids_resp_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid);

/** @brief Decode function for request structure
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] length - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[out] completion_code - completion code for response structure
 *  @param[out] eid_pool_size - EID Pool Size field of response for set eid command
 *  @param[out] status - status field of response structure for
 *			  set eid command
 *  @param[out] eid_set - EID Setting field of response for set eid command
 *  @return decode enum type which tells error or success
 */
decode_rc mctp_decode_set_eid_resp(const struct mctp_msg *response,
				   const size_t length,
				   struct mctp_ctrl_msg_hdr *ctrl_hdr,
				   uint8_t *completion_code,
				   uint8_t *eid_pool_size, uint8_t *status,
				   mctp_eid_t *eid_set);

/** @brief Decode function for request structure
 *
 *  @param[in] response - Response structure to be decoded
 *  @param[in] length - Length of response structure
 *  @param[out] ctrl_hdr - header for response structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[out] completion_code - completion code for response structure
 *  @param[out] uuid - UUID field of response for set get uuid command
 *  @return decode enum type which tells error or success
 */
decode_rc mctp_decode_get_uuid_resp(const struct mctp_msg *response,
				    const size_t length,
				    struct mctp_ctrl_msg_hdr *ctrl_hdr,
				    uint8_t *completion_code, guid_t *uuid);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_DECODE_RESPONSE_H */
