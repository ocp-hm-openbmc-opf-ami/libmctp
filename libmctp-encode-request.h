/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_ENCODE_REQUEST_H
#define _LIBMCTP_ENCODE_REQUEST_H

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Encode function for request structure
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[in] target_eid - target eid of request of resolve eid command
 *  @return encode enum type which tells error or success
 */
encode_decode_rc mctp_encode_resolve_eid_req(struct mctp_msg *request,
					     const size_t length,
					     uint8_t rq_dgram_inst,
					     uint8_t target_eid);

/** @brief Encode function for request structure
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[in] op - operation field of request structure for  allocate eid command
 *  @param[in] pool_size - eid pool size field of request structure for  allocate eid command
 *  @param[in] starting_eid - starting eid field of request structure for  allocate eid command
 *  @return encode enum type which tells error or success
 */
encode_decode_rc
mctp_encode_allocate_endpoint_id_req(struct mctp_msg *request,
				     const size_t length, uint8_t rq_dgram_inst,
				     mctp_ctrl_cmd_allocate_eids_req_op op,
				     uint8_t pool_size, uint8_t starting_eid);

/** @brief Encode function for request structure
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[in] op - operation field of request structure for  set eid command
 *  @param[in] eid - eid field of request structure for  set eid command
 *  @return encode enum type which tells error or success
 */
encode_decode_rc mctp_encode_set_eid_req(struct mctp_msg *request,
					 const size_t length,
					 uint8_t rq_dgram_inst,
					 mctp_ctrl_cmd_set_eid_op op,
					 uint8_t eid);

/** @brief Encode function for request structure
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @return encode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_uuid_req(struct mctp_msg *request,
					  const size_t length,
					  uint8_t rq_dgram_inst);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ENCODE_REQUEST_H */
