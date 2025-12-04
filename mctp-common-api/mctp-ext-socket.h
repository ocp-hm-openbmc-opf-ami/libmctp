
#ifndef __MCTP_EXT_SOCKET_H__
#define __MCTP_EXT_SOCKET_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MCTP_CTRL_TXRX_TIMEOUT_16SECS 16

mctp_requester_rc_t mctp_msg_client_with_binding_send(
	mctp_eid_t dest_eid, int mctp_fd, const uint8_t *mctp_req_msg,
	size_t req_msg_len, const uint8_t *mctp_hdr_msg,
	const mctp_binding_ids_t *bind_id, void *mctp_binding_info,
	size_t mctp_binding_len);
/**
 * @brief Read MCTP socket. If there's data available, return success only if
 *        data is a MCTP message.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[out] mctp_resp_msg - *mctp_resp_msg will point to MCTP msg,
 *             this function allocates memory, caller to free(*mctp_resp_msg) on
 *             success.
 * @param[out] resp_msg_len - caller owned pointer that will be made point to
 *             the size of the MCTP msg.
 *
 * @return int (errno may be set). failure is returned even
 *         when data was read, but wasn't a MCTP response message
 */
mctp_requester_rc_t mctp_client_sync_recv(mctp_eid_t *eid, int mctp_fd,
					  uint8_t **mctp_resp_msg,
					  size_t *resp_msg_len,
					  uint8_t **mctp_hdr_msg,
					  uint16_t *remote_id);
					  /**
 * @brief Write MCTP socket. If the data is sent out, return success.
 *
 * @param[in] eid - destination MCTP eid
 * @param[in] mctp_fd - MCTP socket fd
 * @param[in] mctp_req_msg - the request message will be sent out.
 * @param[in] req_msg_len - the length of the request message.
 *
 * @return int (errno may be set). failure is returned.
 */
mctp_requester_rc_t mctp_client_sync_send(mctp_eid_t dest_eid, int mctp_fd,
				     uint8_t msgtype,
				     const uint8_t *mctp_req_msg,
				     size_t req_msg_len,
					 uint8_t msgtag);		

mctp_requester_rc_t mctp_endpoint_socket_init(int *intf, mctp_eid_t,
					 uint8_t msgtype, time_t timeout);	
#ifdef __cplusplus
}
#endif
#endif
