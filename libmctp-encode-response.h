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
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] bridge_eid - Bridge eid field of response structure for  resolve eid command
 *  @param[in] address - Physical address field of response structure for  resolve eid command
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
 *  @param[in] rq_dgram_inst - request datagram instance of header  structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] op - operation field of response structure for  allocate eid command
 *  @param[in] eid_pool_size - eid pool size field of response structure for  allocate eid command
 *  @param[in] first_eid - first eid field of response structure for  allocate eid command
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
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] eid_pool_size - eid pool size field of response structure for  set eid command
 *  @param[in] status - status field of response structure for  set eid command
 *  @param[in] eid_set - eid setting field of response structure for  set eid command
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
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[in] completion_code - completion code for response structure
 *  @param[in] uuid - UUID field of response structure for  get uuid command
 *  @return encode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_uuid_resp(struct mctp_msg *response,
					   size_t *length,
					   uint8_t rq_dgram_inst,
					   uint8_t completion_code,
					   const guid_t *uuid);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ENCODE_RESPONSE_H */
