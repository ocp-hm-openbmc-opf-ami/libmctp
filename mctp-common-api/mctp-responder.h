/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef __MCTP_RESPONDER_H__
#define __MCTP_RESPONDER_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-discovery-common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes */

mctp_ret_codes_t
mctp_prepare_responder_discovery_send_response(int sock_fd, mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, uint16_t remote_id, struct mctp_ctrl_cmd_prepare_ep_discovery* prep_ep_discovery_req);

mctp_ret_codes_t mctp_responder_discovery_send_response(int sock_fd,
						mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, uint16_t remote_id, struct mctp_ctrl_cmd_ep_discovery* ep_discovery);
mctp_ret_codes_t mctp_responder_set_eid_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, uint16_t remote_id, struct mctp_ctrl_cmd_set_eid *set_eid_req);
mctp_ret_codes_t mctp_responder_get_eid_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, uint16_t remote_id, mctp_eid_t pci_own_eid, struct mctp_ctrl_cmd_get_eid *get_eid_req);
mctp_ret_codes_t mctp_responder_get_uuid_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, uint16_t remote_id, struct mctp_ctrl_cmd_get_uuid *get_uuid_req);
mctp_ret_codes_t mctp_responder_get_mctp_ver_support_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, uint16_t remote_id, struct mctp_ctrl_cmd_get_mctp_ver_support *get_mctp_ver_support_req);					   					   
mctp_ret_codes_t mctp_responder_get_msg_type_support_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, uint16_t remote_id, struct mctp_ctrl_cmd_get_msg_type_support *get_msg_type_support_req);					   					   
mctp_ret_codes_t mctp_responder_get_vdm_support_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, uint16_t remote_id, struct mctp_ctrl_cmd_get_vdm_support *get_vdm_support_req);					   					   

int mctp_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
				    size_t resp_msg_len);
int mctp_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
			       size_t resp_msg_len);			   
#ifdef __cplusplus
}
#endif

#endif /* __MCTP_RESPONDER_H__ */