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
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 *structure definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst; uint8_t
 *				command_code;}
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
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 *structure definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst; uint8_t
 *				command_code;}
 *  @param[in] op - operation field of request structure for  allocate eid
 *				command
 *  @param[in] pool_size - eid pool size field of request structure for allocate
 *				eid command
 *  @param[in] starting_eid - starting eid field of request structure for
 *				allocate eid command
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
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 *structure definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst; uint8_t
 *				command_code;}
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
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 *structure definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst; uint8_t
 *				command_code;}
 *  @return encode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_uuid_req(struct mctp_msg *request,
					  const size_t length,
					  uint8_t rq_dgram_inst);

/** @brief Encode function for get networkid request
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 * 				structure
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_networkid_req(struct mctp_msg *request,
					       const size_t length,
					       uint8_t rq_dgram_inst);

/** @brief Encode function for get routing table request
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 * 				structure
 *  @param[in] entry_handle - entry_handle of request of get_routing_table
 * 				command
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_routing_table_req(struct mctp_msg *request,
						   const size_t length,
						   uint8_t rq_dgram_inst,
						   uint8_t entry_handle);

/** @brief Encode function for get version support request
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 * 				structure
 *  @param[in] msg_type_number - msg_type_number of request of get_ver_support
 * 				command
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_ver_support_req(struct mctp_msg *request,
						 const size_t length,
						 uint8_t rq_dgram_inst,
						 uint8_t msg_type_number);

/** @brief Encode function for get eid request
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 * 				structure
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_eid_req(struct mctp_msg *request,
					 const size_t length,
					 uint8_t rq_dgram_inst);

/** @brief Encode function for getVDM support request
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 * 				structure
 *  @param[out] vid_set_selector - vid_set_selector of getVDM support command
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_get_vdm_support_req(struct mctp_msg *request,
						 const size_t length,
						 uint8_t rq_dgram_inst,
						 uint8_t vid_set_selector);

/** @brief Encode function for prepare endpoint discovery request
 *
 *  @param[out] request - Request structure to be encoded
 *  @param[in] length - Length of request structure
 *  @param[in] rq_dgram_inst - request datagram instance of header for request
 * 				structure
 *  @return encode_decode enum type which tells error or success
 */
encode_decode_rc mctp_encode_prepare_endpoint_discovery_req(
	struct mctp_msg *request, const size_t length, uint8_t rq_dgram_inst);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ENCODE_REQUEST_H */
