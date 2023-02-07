/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef _LIBMCTP_DECODE_REQUEST_H
#define _LIBMCTP_DECODE_REQUEST_H

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Decode function for request structure
 *
 *  @param[in] request - Request structure to be decoded
 *  @param[in] length - Length of request structure
 *  @param[out] ctrl_hdr - header for request structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[out] target_eid - target eid of resolve eid command
 *  @return decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_resolve_eid_req(const struct mctp_msg *request,
					     const size_t length,
					     struct mctp_ctrl_msg_hdr *ctrl_hdr,
					     uint8_t *target_eid);

/** @brief Decode function for request structure
 *
 *  @param[in] request - Request structure to be decoded
 *  @param[in] length - Length of request structure
 *  @param[out] ctrl_hdr - header for request structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[out] op - operation field for allocate eid command
 *  @param[out] eid_pool_size - eid_pool_size field for allocate eid command
 *  @param[out] first_eid - first_eid field for allocate eid command
 *  @return decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_allocate_endpoint_id_req(
	const struct mctp_msg *request, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr,
	mctp_ctrl_cmd_allocate_eids_req_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid);

/** @brief Decode function for request structure
 *
 *  @param[in] request - Request structure to be decoded
 *  @param[in] length - Length of request structure
 *  @param[out] ctrl_hdr - header for request structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @param[out] op - operation field for set eid command
 *  @param[out] eid - eid field for set eid command
 *  @return decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_set_eid_req(const struct mctp_msg *request,
					 const size_t length,
					 struct mctp_ctrl_msg_hdr *ctrl_hdr,
					 mctp_ctrl_cmd_set_eid_op *op,
					 uint8_t *eid);

/** @brief Decode function for request structure
 *
 *  @param[in] request - Request structure to be decoded
 *  @param[in] length - Length of request structure
 *  @param[out] ctrl_hdr - header for request structure 
 *			   definition: {uint8_t ic_msg_type;uint8_t rq_dgram_inst;
 *			   uint8_t command_code;}
 *  @return decode enum type which tells error or success
 */
encode_decode_rc mctp_decode_get_uuid_req(const struct mctp_msg *request,
					  const size_t length,
					  struct mctp_ctrl_msg_hdr *ctrl_hdr);

/** @brief Decode function for get networkid request
 *
 *  @param[in] request - Request structure to be decoded
 *  @param[in] length - Length of request structure
 *  @param[out] ctrl_hdr - header for request structure 
 *  @return encode_decode enum type which tells error or success
 */	
encode_decode_rc
mctp_decode_get_networkid_req(const struct mctp_msg *request,
			      const size_t length,
			      struct mctp_ctrl_msg_hdr *ctrl_hdr);

/** @brief Decode function for get routing table request
 *
 *  @param[in] request - Request structure to be decoded
 *  @param[in] length - Length of request structure
 *  @param[out] ctrl_hdr - header for request structure 
 *  @param[out] entry_handle - entry handle for get_routing_table cmd
 *  @return encode_decode enum type which tells error or success
 */	
encode_decode_rc mctp_decode_get_routing_table_req(
	const struct mctp_msg *request, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *entry_handle);

/** @brief Decode function for get version support request
 *
 *  @param[in] request - Request structure to be decoded
 *  @param[in] length - Length of request structure
 *  @param[out] ctrl_hdr - header for request structure 
 *  @param[out] msg_type_number - msg_type_number for get_ver_support cmd
 *  @return encode_decode enum type which tells error or success
 */	
encode_decode_rc mctp_decode_get_ver_support_req(
	const struct mctp_msg *request, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *msg_type_number);

/** @brief Decode function for get eid request
 *
 *  @param[in] request - Request structure to be decoded
 *  @param[in] length - Length of request structure
 *  @param[out] ctrl_hdr - header for request structure 
 *  @return encode_decode enum type which tells error or success
 */	
encode_decode_rc mctp_decode_get_eid_req(const struct mctp_msg *request,
					 const size_t length,
					 struct mctp_ctrl_msg_hdr *ctrl_hdr);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_DECODE_REQUEST_H */
