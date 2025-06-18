/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef __MCTP_REQUESTER_H__
#define __MCTP_REQUESTER_H__

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
mctp_ret_codes_t mctp_requester_set_eid_send_request(int sock_fd,
					   mctp_binding_ids_t bind_id,
					   mctp_ctrl_cmd_set_eid_op op,
					   uint8_t eid,
					   mctp_eid_t pci_own_eid,
					   int g_target_bdf);

mctp_ret_codes_t mctp_requester_alloc_eid_send_request(
	int sock_fd, mctp_binding_ids_t bind_id, mctp_eid_t assigned_eid,
	mctp_ctrl_cmd_set_eid_op op, uint8_t eid_count, uint8_t eid_start, uint16_t remote_id, mctp_eid_t pci_own_eid);

int mctp_requester_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len,
			      uint8_t *eid, size_t *eid_count);

int mctp_requester_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len, mctp_eid_t *eid_pool_start, size_t * eid_pool_size);

int mctp_requester_get_routing_table_get_response(mctp_ctrl_t *ctrl, mctp_eid_t eid, mctp_binding_ids_t bind_id,
					uint8_t *mctp_resp_msg,
					size_t resp_msg_len,
					bool remove_duplicates,
                    mctp_eid_t pci_own_eid,
					uint8_t * entry_hdl);

mctp_ret_codes_t mctp_requester_get_routing_table_send_request(int sock_fd,
						     mctp_binding_ids_t bind_id,
						     mctp_eid_t dest_eid,
						     uint8_t entry_handle,
                             mctp_eid_t pci_own_eid,
                             uint16_t remote_id);

mctp_ret_codes_t mctp_requester_get_endpoint_uuid_send_request(int sock_fd,
						     mctp_binding_ids_t bind_id,
						     mctp_eid_t dest_eid,
						     mctp_eid_t g_pci_own_eid,
						     uint16_t remote_id);

mctp_ret_codes_t mctp_requester_get_vdm_support_send_request(int sock_fd,
						     mctp_binding_ids_t bind_id,
						     mctp_eid_t dest_eid,
						     mctp_eid_t pci_own_eid,
						     uint16_t remote_id,
							 uint8_t v_id_set_selector);

mctp_ret_codes_t mctp_requester_get_vdm_support_send_response(
							 mctp_eid_t eid,
							 uint8_t *mctp_resp_msg,
							 size_t resp_msg_len,
							 uint8_t *v_id_set_selector
							 );


mctp_ret_codes_t mctp_requester_get_msg_type_send_request(int sock_fd,
						   mctp_binding_ids_t bind_id,
						   mctp_eid_t dest_eid,
                           mctp_eid_t pci_own_eid,
                           uint16_t remote_id);	

mctp_ret_codes_t mctp_requester_prepare_ep_discovery_send_request(int sock_fd,
                           mctp_binding_ids_t bind_id,
                           mctp_eid_t pci_own_eid,
						   int g_target_bdf);	

mctp_ret_codes_t mctp_requester_ep_discovery_send_request(int sock_fd,
						mctp_binding_ids_t bind_id,
						mctp_eid_t pci_own_eid, 
						int g_target_bdf);

#ifdef __cplusplus
}
#endif

#endif /* #define __MCTP_REQUESTER_H__ */