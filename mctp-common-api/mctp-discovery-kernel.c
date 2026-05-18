/*
 * SPDX-FileCopyrightText: Copyright (c)  NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "libmctp-cmds.h"
#include "libmctp-smbus.h"

#include "mctp-discovery-kernel.h"
#include "mctp-discovery-common.h"

#include "mctp-ctrl.h"
#include "mctp-encode.h"
#include "mctp-ctrl-log.h"
#include "mctp-json.h"
#include "mctp-ext-sdbus.h"
#include "mctp-discovery-endpoint.h"
#include "mctp-discovery-busowner.h"
#include "mctp-utils.h"
#include "libmctp-astpcie.h"

#include "mctp-netlink.h"
#include "mctp-ctrl-cmdline.h"
#include "linux/mctp.h"
#include  "mctp-ext-socket.h"

extern uint8_t g_eid_pool_size;
extern uint8_t g_eid_pool_start;
extern mctp_routing_table_t *g_routing_table_entries;
extern const uint8_t MCTP_ROUTING_ENTRY_START;
extern mctp_msg_type_table_t *g_msg_type_entries;

static mctp_eid_t g_kernel_bridge_eid;
static mctp_eid_t g_kernel_reject_set_eid = 0;
static u_int16_t g_remote_id;

/* bridge address variable */
uint8_t g_pci_bridge_address[PCIE_VDM_ADDR_LEN];

/* Helper function to handle kernel-specific routing operations */
int mctp_kernel_setup_routing_entry(struct get_routing_table_entry *routing_table_entry)
{
	int rc = 0;

	/* Validate input parameter */
	if (!routing_table_entry) {
		MCTP_CTRL_ERR("%s: Invalid routing table entry parameter\n", __func__);
		return -1;
	}

	/* Add route for the EID */
	if (mctp_nl_add_route(routing_table_entry->starting_eid) < 0) {
		MCTP_CTRL_ERR("%s: Failed to add route for eid %d\n",
			      __func__, routing_table_entry->starting_eid);
		rc = -1; /* Mark error but continue with cleanup */
	}

	/* Prepare and update hardware info based on binding type */
	if (routing_table_entry->phys_transport_binding_id == MCTP_BINDING_PCIE &&
	    routing_table_entry->phys_address_size == 2) {
		/* PCIe VDM requires 3 bytes: route_type + BDF */
		uint8_t pcie_addr[PCIE_VDM_ADDR_LEN];
		/* Set route type based on command type */
		pcie_addr[0] = PCIE_ROUTE_BY_ID; /* Route type = 2 (routed to ID) */
		pcie_addr[1] = routing_table_entry->phys_address[0]; /* BDF low byte */
		pcie_addr[2] = routing_table_entry->phys_address[1]; /* BDF high byte */
		
		MCTP_CTRL_DEBUG("%s: PCIe VDM address setup - Route type: %d, BDF: 0x%02x%02x\n", 
				__func__, pcie_addr[0], pcie_addr[2], pcie_addr[1]);
		
		mctp_update_endpoint_hwinfo(pcie_addr, PCIE_VDM_ADDR_LEN);
	} else if (routing_table_entry->phys_transport_binding_id == MCTP_BINDING_VDM && 
		   routing_table_entry->phys_address_size == 2) {
		/* For VDM devices, use match_bridge_routing_entry to find correct bridge address */
		uint8_t pcie_addr[PCIE_VDM_ADDR_LEN];
		uint16_t bridge_bdf;
		int original_bdf = (routing_table_entry->phys_address[0] << 8) | 
				   routing_table_entry->phys_address[1];
		
		/* Create a temporary routing entry for match_bridge_routing_entry */
		mctp_routing_table_t temp_routing_entry;
		memcpy(&temp_routing_entry.routing_table, routing_table_entry, 
		       sizeof(struct get_routing_table_entry));
		
		/* Find the bridge BDF using match_bridge_routing_entry */
		bridge_bdf = match_bridge_routing_entry(&temp_routing_entry, original_bdf);
		
		/* Check if bridge BDF is same as original BDF */
		if (bridge_bdf == original_bdf) {
			MCTP_CTRL_DEBUG("%s: VDM binding - Bridge BDF same as original BDF (0x%04x), using global bridge address\n", 
					__func__, original_bdf);
			mctp_update_endpoint_hwinfo(g_pci_bridge_address, PCIE_VDM_ADDR_LEN);
		} else {
			/* Set up PCIe VDM address with bridge BDF */
			pcie_addr[0] = PCIE_ROUTE_BY_ID; /* Route type = 2 (routed to ID) */
			pcie_addr[1] = (uint8_t)((bridge_bdf >> 8) & 0xFF); /* BDF high byte */
			pcie_addr[2] = (uint8_t)(bridge_bdf & 0xFF);        /* BDF low byte */
			
			MCTP_CTRL_DEBUG("%s: VDM binding - Original BDF: 0x%04x, Bridge BDF: 0x%04x, Route type: %d\n", 
					__func__, original_bdf, bridge_bdf, pcie_addr[0]);
			
			mctp_update_endpoint_hwinfo(pcie_addr, PCIE_VDM_ADDR_LEN);
		}
	} else {
		MCTP_CTRL_DEBUG("%s: Using physical address directly - binding: %d, size: %d\n", 
				__func__, routing_table_entry->phys_transport_binding_id, 
				routing_table_entry->phys_address_size);
		mctp_update_endpoint_hwinfo(routing_table_entry->phys_address, 
					   routing_table_entry->phys_address_size);
	}

	/* Add neighbor entry for the EID */
	if (mctp_nl_add_neigh(routing_table_entry->starting_eid) < 0) {
		MCTP_CTRL_ERR("%s: Failed to add neigh for eid %d\n",
			      __func__, routing_table_entry->starting_eid);
		rc = -1; /* Mark error but continue with cleanup */
	}
	
	MCTP_CTRL_DEBUG("%s: Kernel routing setup completed for EID %d, result: %d\n", 
			__func__, routing_table_entry->starting_eid, rc);
	
	return rc;
}

/* Helper function to setup all routing entries from global routing table to kernel */
int mctp_kernel_setup_all_routing_entries(void)
{
	int rc = 0;
	int success_count = 0;
	int total_entries = 0;
	mctp_routing_table_t *routing_entry = NULL;

	/* Check if global routing table exists */
	if (!g_routing_table_entries) {
		MCTP_CTRL_WARN("%s: No routing table entries found in global table\n", __func__);
		return 0; /* Not an error, just no entries to process */
	}

	MCTP_CTRL_DEBUG("%s: Starting to setup all routing entries from global table\n", __func__);

	/* Iterate through all routing table entries */
	routing_entry = g_routing_table_entries;
	while (routing_entry) {
		total_entries++;
		
		MCTP_CTRL_DEBUG("%s: Processing routing entry %d - EID: %d, Transport: %d\n", 
				__func__, total_entries, 
				routing_entry->routing_table.starting_eid,
				routing_entry->routing_table.phys_transport_binding_id);

		/* Setup individual routing entry using existing function */
		int entry_result = mctp_kernel_setup_routing_entry(&routing_entry->routing_table);
		
		if (entry_result == 0) {
			success_count++;
			MCTP_CTRL_DEBUG("%s: Successfully setup routing entry for EID %d\n", 
					__func__, routing_entry->routing_table.starting_eid);
		} else {
			MCTP_CTRL_ERR("%s: Failed to setup routing entry for EID %d, error: %d\n", 
				      __func__, routing_entry->routing_table.starting_eid, entry_result);
			rc = -1; /* Mark that we had failures, but continue processing */
		}

		/* Move to next entry */
		routing_entry = routing_entry->next;
	}

	MCTP_CTRL_INFO("%s: Completed routing table setup - Total: %d, Success: %d, Failed: %d\n", 
		       __func__, total_entries, success_count, (total_entries - success_count));

	/* Return 0 if all succeeded, -1 if any failed */
	return (success_count == total_entries) ? 0 : rc;
}

/* Send function for Get MCTP version support */
mctp_ret_codes_t mctp_kernel_get_mctp_ver_support_request(int sock_fd, uint8_t eid)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_mctp_ver_support get_mctp_ver_support;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;
    struct mctp_hdr mctp_hdr = {1, MCTP_EID_NULL, MCTP_EID_NULL, MCTP_TAG_OWNER};

	(void)eid;

	/* Set destination EID */
	dest_eid = 0;

	/* Encode Get MCTP version support message */
	req_ret = mctp_encode_ctrl_cmd_get_ver_support(
		&get_mctp_ver_support, MCTP_MESSAGE_TYPE_MCTP_CTRL);

	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &get_mctp_ver_support,
	       sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support));

	mctp_print_req_msg(&ep_req, "MCTP_GET_VERSION_SUPPORT_REQUEST",
			   msg_len);

	/* TBD: ep request set eid issue */
	ep_req.data[0] = 0;

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_set_eid), (const uint8_t*) &mctp_hdr, &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Set Endpoint ID */
mctp_ret_codes_t mctp_kernel_set_eid_send_request(int sock_fd,
					       mctp_ctrl_cmd_set_eid_op op,
					       uint8_t eid)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_set_eid set_eid_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;
    struct mctp_hdr mctp_hdr = {1, MCTP_EID_NULL, MCTP_EID_NULL, MCTP_TAG_OWNER};

	/* Set destination EID as NULL */
	dest_eid = MCTP_EID_NULL;

	/* Encode Set Endpoint ID message */
	req_ret = mctp_encode_ctrl_cmd_set_eid(&set_eid_req, op, eid);

	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_set_eid) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &set_eid_req, sizeof(struct mctp_ctrl_cmd_set_eid));

	mctp_print_req_msg(&ep_req, "MCTP_SET_EP_REQUEST", msg_len);

	/* TBD: ep request set eid issue */
	ep_req.data[0] = 0;

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_set_eid), (const uint8_t*) &mctp_hdr, &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Set Endpoint ID */
int mctp_kernel_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len,
				  uint8_t eid, uint8_t *eid_count)
{
	bool req_ret;
	struct mctp_ctrl_resp_set_eid *set_eid_resp;

	(void)eid;

	mctp_print_resp_msg(
		(struct mctp_ctrl_resp *)mctp_resp_msg, "MCTP_SET_EP_RESPONSE",
		resp_msg_len - sizeof(struct mctp_ctrl_cmd_msg_hdr));

	set_eid_resp = (struct mctp_ctrl_resp_set_eid *)mctp_resp_msg;

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_set_eid(set_eid_resp);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);

		/* Check wheteher device is ready or not */
		if (set_eid_resp->completion_code ==
		    MCTP_CONTROL_MSG_STATUS_ERROR_NOT_READY) {
			MCTP_CTRL_DEBUG(
				"%s: Device [eid: %d] is not ready yet..\n",
				__func__, set_eid_resp->eid_set);
			return MCTP_RET_DEVICE_NOT_READY;
		}

		return MCTP_RET_ENCODE_FAILED;
	}

	/* Check whether the EID is accepted by the device or not */
	if (set_eid_resp->status & MCTP_SETEID_ASSIGN_STATUS_REJECTED) {
		MCTP_CTRL_DEBUG(
			"%s: Set Endpoint id: 0x%x, Status:0x%x (Rejected by the device)\n",
			__func__, set_eid_resp->eid_set, set_eid_resp->status);

		/* Get the EID from the bridge (FPGA) */
		g_kernel_bridge_eid = set_eid_resp->eid_set;
		g_kernel_reject_set_eid = set_eid_resp->eid_set;	
	} else {
		MCTP_CTRL_DEBUG(
			"%s: Set Endpoint id: 0x%x (Accepted by the device)\n",
			__func__, set_eid_resp->eid_set);
	}

#ifdef MCTP_IN_KERNEL
	if (mctp_nl_add_route(set_eid_resp->eid_set) < 0) {
		MCTP_CTRL_ERR("%s: Failed to add route for eid %d\n", __func__,
				set_eid_resp->eid_set);
	}

	if (mctp_nl_add_neigh(set_eid_resp->eid_set) < 0) {
		MCTP_CTRL_ERR("%s: Failed to add neigh for eid %d\n", __func__,
				set_eid_resp->eid_set);
	}
#endif

	/* Check whether the device requires EID pool allocation or not */
	if (set_eid_resp->status & MCTP_SETEID_ALLOC_STATUS_EID_POOL_REQ) {
		MCTP_CTRL_DEBUG(
			"%s: Endpoint require EID pool allocation: 0x%x (status)\n",
			__func__, set_eid_resp->status);

		/* Get the EID pool size from response */
		g_eid_pool_size = set_eid_resp->eid_pool_size;

		/* update the eid_count pointer */
		*eid_count = set_eid_resp->eid_pool_size;

		MCTP_CTRL_DEBUG("%s: g_kernel_eid_pool_size: 0x%x\n", __func__,
				g_eid_pool_size);

	} else {
		MCTP_CTRL_DEBUG(
			"%s: Endpoint doesn't require EID pool allocation: 0x%x (status)\n",
			__func__, set_eid_resp->status);

		/* Reset the EID pool size */
		g_eid_pool_size = 0;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Allocate Endpoint ID */
mctp_ret_codes_t mctp_kernel_alloc_eid_send_request(int sock_fd,
						 mctp_eid_t assigned_eid,
						 mctp_ctrl_cmd_set_eid_op op,
						 uint8_t eid_count,
						 uint8_t eid_start)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_alloc_eid set_eid_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;
    struct mctp_hdr mctp_hdr = {1, MCTP_EID_NULL, MCTP_EID_NULL, MCTP_TAG_OWNER};

	/* Set destination EID as NULL */
	dest_eid = assigned_eid;

	/* Allocate Endpoint ID's message */
	req_ret = mctp_encode_ctrl_cmd_alloc_eid(&set_eid_req,
						 (mctp_ctrl_cmd_alloc_eid_op)op,
						 eid_count, eid_start);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_alloc_eid) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &set_eid_req, sizeof(struct mctp_ctrl_cmd_alloc_eid));

	/* Force set to 0 */
	ep_req.data[0] = 0;

	mctp_print_req_msg(&ep_req, "MCTP_ALLOCATE_EP_ID_REQUEST", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_alloc_eid), (const uint8_t*) &mctp_hdr, &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Allocate Endpoint ID */
int mctp_kernel_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len)
{
	bool req_ret;
	struct mctp_ctrl_resp_alloc_eid *alloc_eid_resp;

	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
			    "MCTP_ALLOCATE_EP_ID_RESPONSE",
			    resp_msg_len -
				    sizeof(struct mctp_ctrl_cmd_msg_hdr));

	alloc_eid_resp = (struct mctp_ctrl_resp_alloc_eid *)mctp_resp_msg;

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_alloc_eid(alloc_eid_resp);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Check whether allocation was accepted or not */
	if (alloc_eid_resp->alloc_status == MCTP_ALLOC_EID_REJECTED) {
		MCTP_CTRL_ERR(
			"%s: Alloc Endpoint ID rejected/already allocated by another bus owner\n",
			__func__);
	}

	/* Get EID pool size and the EID start */
	g_eid_pool_size = alloc_eid_resp->eid_pool_size;
	g_eid_pool_start = alloc_eid_resp->eid_start;

	MCTP_CTRL_DEBUG("%s: g_eid_pool_size: %d, eid_start: %d\n", __func__,
			g_eid_pool_size, g_eid_pool_start);

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get routing table */
mctp_ret_codes_t mctp_kernel_get_routing_table_send_request(int sock_fd,
							 mctp_eid_t eid,
							 uint8_t entry_handle)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_routing_table get_routing_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;
	static int entry_count = 0;
    struct mctp_hdr mctp_hdr = {1, MCTP_EID_NULL, MCTP_EID_NULL, MCTP_TAG_OWNER};

	(void)eid;

	/* Set destination EID as NULL */
	dest_eid = MCTP_EID_NULL;

	/* Get routing table request message */
	req_ret = mctp_encode_ctrl_cmd_get_routing_table(
		&get_routing_req, entry_handle + entry_count);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Increment the entry count */
	entry_count++;

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_routing_table) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &get_routing_req,
	       sizeof(struct mctp_ctrl_cmd_get_routing_table));

	mctp_print_req_msg(&ep_req, "MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST",
			   msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_get_routing_table), (const uint8_t*) &mctp_hdr, &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get routing table */
int mctp_kernel_get_routing_table_get_response(int sock_fd, mctp_eid_t eid,
					    uint8_t *mctp_resp_msg,
					    size_t resp_msg_len,
						mctp_eid_t own_eid)
{
	bool req_ret;
	struct mctp_ctrl_resp_get_routing_table *routing_table;
	int ret;

	(void)sock_fd;
	(void)eid;

	MCTP_CTRL_TRACE("%s: Get EP reesponse\n", __func__);

	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
			    "MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE",
			    resp_msg_len -
				    sizeof(struct mctp_ctrl_cmd_msg_hdr));

	routing_table =
		(struct mctp_ctrl_resp_get_routing_table *)mctp_resp_msg;

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_get_routing_table(routing_table);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);

		/* Check wheteher device is ready or not */
		if (routing_table->completion_code ==
		    MCTP_CONTROL_MSG_STATUS_ERROR_NOT_READY) {
			MCTP_CTRL_DEBUG("%s: Device is not ready yet..\n",
					__func__);
			return MCTP_RET_DEVICE_NOT_READY;
		}
		return MCTP_RET_ENCODE_FAILED;
	}

	MCTP_CTRL_DEBUG("%s: Next entry handle: %d, Number of entries: %d\n",
			__func__, routing_table->next_entry_handle,
			routing_table->number_of_entries);

	/* Check if the routing table exist */
	if (routing_table->number_of_entries) {
		struct get_routing_table_entry routing_table_entry;

		/* Copy the routing table entries to local routing table */
		memcpy(&routing_table_entry,
		       mctp_resp_msg +
			       sizeof(struct mctp_ctrl_resp_get_routing_table),
		       sizeof(struct get_routing_table_entry));

		/* Dont add the entry to the routing table if the EID is it's own */
		if (routing_table_entry.starting_eid == own_eid) {
			MCTP_CTRL_DEBUG(
				"%s: Found it's own eid: [%d] in the Routing table\n",
				__func__, routing_table_entry.starting_eid);
		} else {
			/* Add the entry to a linked list */
			ret = mctp_routing_entry_add(&routing_table_entry);

			if (ret < 0) {
				MCTP_CTRL_ERR(
					"%s: Failed to update global routing table..\n",
					__func__);
				return MCTP_RET_REQUEST_FAILED;
			}

			/* Print the routing table entry */
			mctp_print_routing_table_entry(
				g_routing_table_entries->id,
				&routing_table_entry);

			/* Length of the Routing table */
			MCTP_CTRL_DEBUG(
				"%s: EID: 0x%x, Routing table length: %d\n",
				__func__, routing_table_entry.starting_eid,
				g_eid_pool_size);
		}

		/* Check if the next routing table exist.. */
		if (routing_table->next_entry_handle != 0xFF) {
			MCTP_CTRL_DEBUG("%s: Next routing entry found %d\n",
					__func__,
					routing_table->next_entry_handle);

			return MCTP_RET_ROUTING_TABLE_FOUND;
		} else {
			MCTP_CTRL_DEBUG("%s: No more routing entries %d\n",
					__func__,
					routing_table->next_entry_handle);
		}
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get UUID */
mctp_ret_codes_t mctp_kernel_get_endpoint_uuid_send_request(int sock_fd,
							 mctp_eid_t eid)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_uuid uuid_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;
    struct mctp_hdr mctp_hdr = {1, MCTP_EID_NULL, MCTP_EID_NULL, MCTP_TAG_OWNER};

	/* Set destination EID */
	dest_eid = eid;

	/* Encode for Get Endpoint UUID message */
	req_ret = mctp_encode_ctrl_cmd_get_uuid(&uuid_req);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_uuid) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &uuid_req, sizeof(struct mctp_ctrl_cmd_get_uuid));

	mctp_print_req_msg(&ep_req, "MCTP_GET_EP_UUID_REQUEST", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_get_uuid), (const uint8_t*) &mctp_hdr, &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get UUID */
int mctp_kernel_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
					size_t resp_msg_len)
{
	bool req_ret;
	struct mctp_ctrl_resp_get_uuid *uuid_resp;
	int ret;
	mctp_uuid_table_t uuid_table;

	/* Trace the Rx message */
	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
			    "MCTP_GET_EP_UUID_RESPONSE",
			    resp_msg_len -
				    sizeof(struct mctp_ctrl_cmd_msg_hdr));

	uuid_resp = (struct mctp_ctrl_resp_get_uuid *)mctp_resp_msg;

	/* Parse the UUID response message */
	req_ret = mctp_decode_resp_get_uuid(uuid_resp);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Update UUID private params to export to upper layer */
	uuid_table.eid = eid;
	memcpy(&uuid_table.uuid.canonical, &uuid_resp->uuid.canonical,
	       sizeof(guid_t));
	uuid_table.next = NULL;

	/* Create a new UUID entry and add to list */
	ret = mctp_uuid_entry_add(&uuid_table);
	if (ret < 0) {
		MCTP_CTRL_ERR("%s: Failed to update global UUID table..\n",
			      __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get Messgae types */
mctp_ret_codes_t mctp_kernel_get_msg_type_request(int sock_fd, mctp_eid_t eid)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_msg_type_support msg_type_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	mctp_eid_t dest_eid;
	mctp_binding_ids_t bind_id;
	struct mctp_smbus_pkt_private pvt_binding;
    struct mctp_hdr mctp_hdr = {1, MCTP_EID_NULL, MCTP_EID_NULL, MCTP_TAG_OWNER};

	/* Set destination EID */
	dest_eid = eid;

	/* Encode for Get Endpoint UUID message */
	req_ret = mctp_encode_ctrl_cmd_get_msg_type_support(&msg_type_req);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_msg_type_support) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &msg_type_req,
	       sizeof(struct mctp_ctrl_cmd_get_msg_type_support));

	mctp_print_req_msg(&ep_req, "MCTP_GET_MSG_TYPE_REQUEST", msg_len);

	/* Send the request message over socket */
	MCTP_CTRL_TRACE("%s: Sending EP request\n", __func__);
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_get_msg_type_support), (const uint8_t*) &mctp_hdr, &bind_id,
		(void *)&pvt_binding, sizeof(pvt_binding));

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_CTRL_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get Messgae types */
int mctp_kernel_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg, size_t resp_msg_len, const char* binding,
				    mctp_eid_t own_eid, const char* iface, uint8_t ifindex, uint8_t network)
{
	bool req_ret;
	struct mctp_ctrl_resp_get_msg_type_support *msg_type_resp;
	int ret;
	mctp_msg_type_table_t msg_type_table;

	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
			    "MCTP_GET_MSG_TYPE_RESPONSE",
			    resp_msg_len -
				    sizeof(struct mctp_ctrl_cmd_msg_hdr));

	/* the minimum message size is 5 bytes:
		eid 1 byte + 3 header bytes + 1 data length field */
	if (resp_msg_len < 5) {
		MCTP_CTRL_ERR(
			"%s: Minimum message size is 5 bytes, but received %zi\n",
			__func__, resp_msg_len);
		return MCTP_RET_REQUEST_FAILED;
	}

	msg_type_resp =
		(struct mctp_ctrl_resp_get_msg_type_support *)mctp_resp_msg;

	/* Parse the Get message type buffer */
	req_ret = mctp_decode_ctrl_cmd_get_msg_type_support(msg_type_resp);
	if (req_ret == false) {
		MCTP_CTRL_ERR("%s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	MCTP_CTRL_DEBUG("%s: EID: %d, Number of supported message types %d\n",
			__func__, eid,
			((struct mctp_ctrl_resp *)mctp_resp_msg)->data[0]);

	/* Update Message type private params to export to upper layer */
	msg_type_table.next = NULL;
	msg_type_table.enabled = true;
	msg_type_table.eid = eid;
	msg_type_table.old_enabled = false;
	msg_type_table.enabled = true;
	msg_type_table.new = true;
	msg_type_table.data_len = ((struct mctp_ctrl_resp *)mctp_resp_msg)
					  ->data[MCTP_MSG_TYPE_DATA_LEN_OFFSET];
	memset(msg_type_table.slot, 0, sizeof(msg_type_table.slot));
	msg_type_table.binding_type = binding;
	msg_type_table.ifname = iface;
	msg_type_table.ifindex = ifindex;
	msg_type_table.own_eid = own_eid;
	msg_type_table.net = network;

	if (msg_type_table.data_len > (MCTP_BTU - 1)) {
		MCTP_CTRL_INFO(
			"%s: EID: %d, Data length: %u, but in the response there is only: %zi\n",
			__func__, eid, msg_type_table.data_len, resp_msg_len);
		msg_type_table.data_len = MCTP_BTU - 1;
	}

	if (msg_type_table.data_len > (resp_msg_len - 5)) {
		MCTP_CTRL_INFO(
			"%s: EID: %d, Data length: %u, but in the response there is only: %zi data bytes\n",
			__func__, eid, msg_type_table.data_len,
			resp_msg_len - 5);
		msg_type_table.data_len = resp_msg_len - 5;
	}

	memcpy(msg_type_table.data,
	       &(((struct mctp_ctrl_resp *)mctp_resp_msg)
			 ->data[MCTP_MSG_TYPE_DATA_OFFSET]),
	       msg_type_table.data_len);

	/* Create a new Msg type entry and add to list */
	ret = mctp_msg_type_entry_add(&msg_type_table);
	if (ret < 0) {
		MCTP_CTRL_ERR("%s: Failed to update global routing table..\n",
			      __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* MCTP discovery response receive routine */
static mctp_ret_codes_t mctp_discover_response(mctp_discovery_mode mode,
					       mctp_eid_t eid, int sock,
					       uint8_t **mctp_resp_msg,
					       size_t *mctp_resp_len,
   						   uint8_t **mctp_hdr_msg)
{
	mctp_requester_rc_t mctp_ret;

	/* Ignore request commands */
	switch (mode) {
	case MCTP_SET_EP_REQUEST:
	case MCTP_ALLOCATE_EP_ID_REQUEST:
	case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:
	case MCTP_GET_EP_UUID_REQUEST:
	case MCTP_GET_MSG_TYPE_REQUEST:
		return MCTP_RET_REQUEST_SUCCESS;

	default:
		break;
	}

	switch (mode) {
	case MCTP_SET_EP_RESPONSE:
	case MCTP_ALLOCATE_EP_ID_RESPONSE:
	case MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE:
	case MCTP_GET_EP_UUID_RESPONSE:
	case MCTP_GET_MSG_TYPE_RESPONSE:

		/* Receive MCTP packets */
		mctp_ret = mctp_client_sync_recv(&eid, sock, mctp_resp_msg,
					    mctp_resp_len, mctp_hdr_msg, &g_remote_id);
		if (mctp_ret != MCTP_REQUESTER_SUCCESS) {
			MCTP_CTRL_DEBUG("%s: Failed to received message %d\n",
				      __func__, mctp_ret);
			return MCTP_RET_REQUEST_FAILED;
		}

		break;

	default:
		MCTP_CTRL_DEBUG("%s: Unknown discovery mode: %d\n", __func__,
				mode);
		break;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Routine to Discover the endpoint devices */
mctp_ret_codes_t mctp_kernel_discover_endpoints(const mctp_cmdline_args_t *cmd,
					     mctp_ctrl_t *ctrl)
{
	static int discovery_mode = MCTP_SET_EP_REQUEST;
	mctp_ret_codes_t mctp_ret;
	mctp_ctrl_cmd_set_eid_op set_eid_op;
	mctp_ctrl_cmd_alloc_eid_op alloc_eid_op;
	uint8_t eid = 0, eid_count = 0, eid_start = 0;
	uint8_t entry_hdl = MCTP_ROUTING_ENTRY_START;
	uint8_t *mctp_resp_msg;
	uint8_t *mctp_hdr_msg = NULL;	
	size_t resp_msg_len;
	int timeout = 0;
	mctp_routing_table_t *routing_entry = NULL;	
	struct mctp_kernel_binding *kernel_binding;	
	kernel_binding = (struct mctp_kernel_binding *) & cmd->kernel.binding[ctrl->active_binding];
	mctp_eid_t local_eid = kernel_binding->own_eid;
	mctp_eid_t bridge_eid = kernel_binding->eid;
	mctp_eid_t eid_pool_start =kernel_binding->eid_pool_start;

	do {
		/* Wait for MCTP response */
		mctp_ret = mctp_discover_response(discovery_mode, bridge_eid,
						  ctrl->sock, &mctp_resp_msg,
						  &resp_msg_len, &mctp_hdr_msg);
		if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
			MCTP_CTRL_ERR("%s: Failed to received message %d\n",
				      __func__, mctp_ret);

			/*
			 * Dont return failure for Get EP UUID and Messgae types as it need to
			 * fetch the next data from the routing table entries.
			 * NOTE: In general it's very unlikely we hit this scenario. If such
			 * failure occurs, then it could be either a firmware issue or
			 * some Hardware issue.
			 */

			if ((discovery_mode != MCTP_GET_EP_UUID_RESPONSE) &&
			    (discovery_mode != MCTP_GET_MSG_TYPE_RESPONSE)) {
				MCTP_CTRL_ERR(
					"%s: Unexpected failure %d, mode[%d]\n",
					__func__, mctp_ret, discovery_mode);
				return MCTP_RET_DISCOVERY_FAILED;
			}
		}

		switch (discovery_mode) {
		case MCTP_SET_EP_REQUEST:

			/* Update the EID operation and EID number */
			set_eid_op = set_eid;
			eid = g_kernel_bridge_eid;

			/* Send the MCTP_SET_EP_REQUEST */
			mctp_ret = mctp_kernel_set_eid_send_request(
				ctrl->sock, set_eid_op, eid);
			if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_KERNEL_SET_EP_REQUEST\n",
					__func__);
				//return MCTP_RET_DISCOVERY_FAILED;
				break;
			}

			/* Wait for the endpoint response */
			discovery_mode = MCTP_SET_EP_RESPONSE;

			break;

		case MCTP_SET_EP_RESPONSE:
			/* Process the MCTP_SET_EP_RESPONSE */
			mctp_ret = mctp_kernel_set_eid_get_response(
				mctp_resp_msg, resp_msg_len, g_kernel_bridge_eid,
				&eid_count);
			/* Free Rx packet */
			free(mctp_resp_msg);
			mctp_resp_msg = NULL;
			free(mctp_hdr_msg);
			mctp_hdr_msg = NULL;					

			/* Retry if the device is not ready */
			if (mctp_ret == MCTP_RET_DEVICE_NOT_READY) {
				/* Make sure it's not timedout before continuing */
				if (timeout < MCTP_DEVICE_SET_EID_TIMEOUT) {
					/* Increment the timeout */
					timeout += MCTP_DEVICE_READY_DELAY;

					/* Set the discover mode as MCTP_SET_EP_REQUEST */
					discovery_mode = MCTP_SET_EP_REQUEST;

					/* Sleep for a while */
#if !USE_FUZZ_CTRL
					sleep(MCTP_DEVICE_READY_DELAY);
#endif
					break;
				}

				MCTP_CTRL_ERR(
					"%s: Timedout[%d] MCTP_EP_DISCOVERY_RESPONSE\n",
					__func__, timeout);
				return MCTP_RET_DISCOVERY_FAILED;
			}

			if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_EP_DISCOVERY_RESPONSE\n",
					__func__);
				return MCTP_RET_DISCOVERY_FAILED;
			}

			/* Reset the timeout */
			timeout = 0;

			/* Next step is to Allocate endpoint IDs request */
			discovery_mode = MCTP_ALLOCATE_EP_ID_REQUEST;

			break;

		case MCTP_ALLOCATE_EP_ID_REQUEST:

			/* Update the Allocate EIDs operation, number of EIDs, Starting EID */
			eid = bridge_eid;
			alloc_eid_op = alloc_req_eid;

			/* Set the start of EID */
			eid_start = eid_pool_start;

			/* Send the MCTP_ALLOCATE_EP_ID_REQUEST */
			mctp_ret = mctp_kernel_alloc_eid_send_request(
				ctrl->sock, eid,
				(mctp_ctrl_cmd_set_eid_op)alloc_eid_op,
				eid_count, eid_start);
			if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_SET_EP_REQUEST\n",
					__func__);
				return MCTP_RET_DISCOVERY_FAILED;
			}

			/* Wait for the endpoint response */
			discovery_mode = MCTP_ALLOCATE_EP_ID_RESPONSE;

			break;

		case MCTP_ALLOCATE_EP_ID_RESPONSE:
			if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: MCTP_ALLOCATE_EP_ID_RESPONSE Failed EID: %d\n",
					__func__, eid_start);
			} else {
				/* Process the MCTP_ALLOCATE_EP_ID_RESPONSE */
				/* Reason for false positive - Checked  freed pointer */
				/* coverity[pass_freed_arg : FALSE] */	
				/* coverity[deref_arg : FALSE] */
				mctp_ret = mctp_kernel_alloc_eid_get_response(
					mctp_resp_msg, resp_msg_len);

				/* Free Rx packet */
				free(mctp_resp_msg);
				mctp_resp_msg = NULL;
				free(mctp_hdr_msg);
				mctp_hdr_msg = NULL;					
				
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_ALLOCATE_EP_ID_RESPONSE\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}
			}
			/* Next step is to get UUID request */
			discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;

			/*
					* Sleep for a while, since the device need to allocate EIDs
					* to downstream devices
					*/
			MCTP_CTRL_DEBUG(
				"%s: MCTP_ALLOCATE_EP_ID_RESPONSE (sleep %d secs)\n",
				__func__, MCTP_DEVICE_GET_ROUTING_DELAY);

			/*
					* Sleep for a while (this is needed for Bridge to prepare the
					* Routing table entries)
					*/
#if !USE_FUZZ_CTRL
			sleep(MCTP_DEVICE_GET_ROUTING_DELAY);
#endif
			break;

		case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:

			/* Send the MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
			mctp_ret = mctp_kernel_get_routing_table_send_request(
				ctrl->sock, eid, entry_hdl);
			if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST\n",
					__func__);
				return MCTP_RET_DISCOVERY_FAILED;
			}

			/* Wait for the endpoint response */
			discovery_mode =
				MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE;

			break;

		case MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE:

			/* Process the MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE */
			mctp_ret = mctp_kernel_get_routing_table_get_response(
				ctrl->sock, eid, mctp_resp_msg, resp_msg_len, local_eid);

			/* Free Rx packet */
			free(mctp_resp_msg);
			mctp_resp_msg = NULL;
			free(mctp_hdr_msg);
			mctp_hdr_msg = NULL;	
			/* Retry if the device is not ready */
			if (mctp_ret == MCTP_RET_DEVICE_NOT_READY) {
				/* Make sure it's not timedout before continuing */
				if (timeout < MCTP_DEVICE_GET_ROUTING_TIMEOUT) {
					/* Increment the timeout */
					timeout += MCTP_DEVICE_READY_DELAY;

					/* Set the discover mode as MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
					discovery_mode =
						MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;

					/* Sleep for a while */
#if !USE_FUZZ_CTRL
					sleep(MCTP_DEVICE_READY_DELAY);
#endif
					break;
				}

				MCTP_CTRL_ERR(
					"%s: Timedout[%d secs]  MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE\n",
					__func__, timeout);
				return MCTP_RET_DISCOVERY_FAILED;
			}

			/* Reset the timeout */
			timeout = 0;

			if (MCTP_RET_DISCOVERY_FAILED == mctp_ret) {
				MCTP_CTRL_ERR(
					"%s: Failed MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE\n",
					__func__);
				return MCTP_RET_DISCOVERY_FAILED;
			}

			/* Check if next routing entry found and set discovery mode accordingly */
			if (MCTP_RET_ROUTING_TABLE_FOUND == mctp_ret) {
				MCTP_CTRL_DEBUG("%s: Next entry found..\n",
						__func__);
				discovery_mode =
					MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;
				break;
			}

			/* Get the start of Routing entry */
			routing_entry = g_routing_table_entries;

			/* Next step is to Get Endpoint UUID request */
			discovery_mode = MCTP_GET_EP_UUID_REQUEST;

			break;

		case MCTP_GET_EP_UUID_REQUEST:

			/* Send the MCTP_GET_EP_UUID_REQUEST */
			if (routing_entry) {
				/* Set the Start of EID */
				eid_start = routing_entry->routing_table
						    .starting_eid;

				MCTP_CTRL_DEBUG(
					"%s: Send UUID Request for EID: 0x%x\n",
					__func__, eid_start);

				mctp_ret =
					mctp_kernel_get_endpoint_uuid_send_request(
						ctrl->sock, eid_start);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_GET_EP_UUID_REQUEST\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}
			}

			/* Wait for the endpoint response */
			discovery_mode = MCTP_GET_EP_UUID_RESPONSE;

			break;

		case MCTP_GET_EP_UUID_RESPONSE:

			if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
				MCTP_CTRL_ERR(
					"%s: MCTP_GET_EP_UUID_RESPONSE Failed EID: %d\n",
					__func__, eid_start);
			} else {
				/* Process the MCTP_GET_EP_UUID_RESPONSE */
				mctp_ret = mctp_kernel_get_endpoint_uuid_response(
					eid_start, mctp_resp_msg, resp_msg_len);

				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: MCTP_GET_EP_UUID_RESPONSE Failed\n",
						__func__);
				}
				/* Free Rx packet */
				free(mctp_resp_msg);
				mctp_resp_msg = NULL;
				free(mctp_hdr_msg);
				mctp_hdr_msg = NULL;				}

			/* Increment the routing entry */
			if (routing_entry) {
				routing_entry = routing_entry->next;
			}

			/* Continue probing all UUID requests */
			if (routing_entry) {
				/* Next step is to Get Endpoint UUID request */
				discovery_mode = MCTP_GET_EP_UUID_REQUEST;
				break;
			}

			/* Get the start of Routing entry */
			routing_entry = g_routing_table_entries;

			discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;

			break;

		case MCTP_GET_MSG_TYPE_REQUEST:

			/* Send the MCTP_GET_EP_UUID_REQUEST */
			if (routing_entry) {
				/* Set the Start of EID */
				eid_start = routing_entry->routing_table
						    .starting_eid;

				MCTP_CTRL_DEBUG(
					"%s: Send Get Msg type Request for EID: 0x%x\n",
					__func__, eid_start);

				mctp_ret = mctp_kernel_get_msg_type_request(
					ctrl->sock, eid_start);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_GET_MSG_TYPE_REQUEST\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}
			}

			/* Wait for the endpoint response */
			discovery_mode = MCTP_GET_MSG_TYPE_RESPONSE;

			break;

		case MCTP_GET_MSG_TYPE_RESPONSE:

			if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
				MCTP_CTRL_ERR(
					"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed EID: %d\n",
					__func__, eid_start);
			} else {
				/* Process the MCTP_GET_MSG_TYPE_RESPONSE */
				mctp_ret = mctp_kernel_get_msg_type_response(
					eid_start, mctp_resp_msg, resp_msg_len, kernel_binding->binding, kernel_binding->own_eid, 
					kernel_binding->interface_name, if_nametoindex(kernel_binding->interface_name), kernel_binding->network);

				/* Free Rx packet */
				free(mctp_resp_msg);
				mctp_resp_msg = NULL;
				free(mctp_hdr_msg);
				mctp_hdr_msg = NULL;	
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed\n",
						__func__);
				}
			}

			/* Increment the routing entry */
			if (routing_entry) {
				routing_entry = routing_entry->next;
			}

			/* Continue probing all Msg type requests */
			if (routing_entry) {
				/* Next step is to Get Endpoint UUID request */
				discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;
				break;
			}

			/* Finally update the global mctp_discovered_endpoints */
			MCTP_CTRL_DEBUG("%s: Completed discovery process..\n",
					__func__);
			discovery_mode = MCTP_FINISH_DISCOVERY;

			break;

		default:
			break;
		}

	} while (discovery_mode != MCTP_FINISH_DISCOVERY);

	/* Display all Routing table details */
	MCTP_CTRL_DEBUG("%s: Obtained Routing table entries\n", __func__);
	mctp_routing_entry_display();

	/* Display all UUID details */
	MCTP_CTRL_DEBUG("%s: Obtained UUID entries\n", __func__);
	mctp_uuid_display();

	/* Display all message type details */
	MCTP_CTRL_DEBUG("%s: Obtained Message type entries\n", __func__);
	mctp_msg_types_display();

	return MCTP_RET_DISCOVERY_SUCCESS;
}

/* Routine to Discover the endpoint devices */
mctp_ret_codes_t
mctp_kernel_discover_static_pool_endpoint(const mctp_cmdline_args_t *cmd,
				       mctp_ctrl_t *ctrl)
{
	static int discovery_mode = MCTP_SET_EP_REQUEST;
	mctp_ret_codes_t mctp_ret;
	mctp_ctrl_cmd_set_eid_op set_eid_op;
	uint8_t eid_count = 0;
	uint8_t *mctp_resp_msg = NULL;
	uint8_t *mctp_hdr_msg = NULL;	
	size_t resp_msg_len;
	int timeout = 0;
	static bool daemon_mode = false;

	struct mctp_kernel_binding *kernel_binding;

	for (size_t i = 0 ; i < cmd->kernel.binding_len ; i++) {
		kernel_binding = (struct mctp_kernel_binding *)  &cmd->kernel.binding[i];
		ctrl->active_binding = i;
		discovery_mode = MCTP_SET_EP_REQUEST;
		int rc = 0;
		
		update_interface_info(
			kernel_binding->interface_name, kernel_binding->dest_slave_addr,  kernel_binding->slave_addr_len,
			kernel_binding->own_eid, kernel_binding->network, kernel_binding->mtu);

		/* SMBUS/I2C require to set NETLINK socket for all slave devices*/
		if ((rc = mctp_nl_socket_init()) < 0) {
			MCTP_CTRL_ERR(
				"%s failed to setup nl_socket for %s eid %d rc %d\n",
				__func__, kernel_binding->interface_name,kernel_binding->own_eid, rc);
			//return MCTP_RET_DISCOVERY_FAILED;
			continue;
		}

		if (kernel_binding->device_role == MCTP_ENDPOINT) {
			mctp_endpoint_mode_discover_endpoints(cmd, ctrl);
			continue;
		} else if (kernel_binding->device_role == MCTP_BUSOWNER) {
			mctp_busowner_mode_discover_endpoints(cmd, ctrl);
			continue;
		} else if (check_endpoint_discovered(kernel_binding->eid))
			continue;
		
		mctp_endpoint_socket_init(&ctrl->sock, kernel_binding->own_eid , 0, MCTP_CTRL_TXRX_TIMEOUT_16SECS);
		do {
			if(daemon_mode) {
				MCTP_SYS_DEBUG("%s: Discovery mode: %d\n", __func__, discovery_mode);
				while(sd_bus_process(ctrl->bus, NULL) > 0) ;
			}

			/* Wait for MCTP response */
			mctp_ret = mctp_discover_response(
				discovery_mode, kernel_binding->eid,
				ctrl->sock, &mctp_resp_msg, &resp_msg_len, &mctp_hdr_msg);

			if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
				MCTP_CTRL_DEBUG(
					"%s: Failed to received message %d\n",
					__func__, mctp_ret);

				if ((discovery_mode !=
				     MCTP_GET_EP_UUID_RESPONSE) &&
				    (discovery_mode !=
				     MCTP_GET_MSG_TYPE_RESPONSE) &&
				    (discovery_mode !=
				     MCTP_SET_EP_RESPONSE)) {
				
					MCTP_CTRL_ERR(
						"%s: Unexpected failure %d, mode[%d]\n",
						__func__, mctp_ret,
						discovery_mode);
					break;
				}
			}

			switch (discovery_mode) {
			case MCTP_SET_EP_REQUEST:
				/* Update the EID operation and EID number */
				set_eid_op = g_kernel_reject_set_eid ? force_eid : set_eid;

				/* Send the MCTP_SET_EP_REQUEST */
				mctp_ret = mctp_kernel_set_eid_send_request(
					ctrl->sock, set_eid_op, kernel_binding->eid);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_KERNEL_SET_EP_REQUEST\n",
						__func__);
					//return MCTP_RET_DISCOVERY_FAILED;
					discovery_mode = MCTP_FINISH_DISCOVERY;
#ifdef MCTP_IN_KERNEL						
						close(ctrl->sock);
#endif

					break;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_SET_EP_RESPONSE;

				break;

			case MCTP_SET_EP_RESPONSE:
				if (mctp_ret == MCTP_RET_REQUEST_SUCCESS) {
					/* Process the MCTP_SET_EP_RESPONSE */
					mctp_ret = mctp_kernel_set_eid_get_response(
						mctp_resp_msg, resp_msg_len, kernel_binding->eid,
						&eid_count);
					/* Free Rx packet */
					free(mctp_resp_msg);
					mctp_resp_msg = NULL;
					free(mctp_hdr_msg);
					mctp_hdr_msg = NULL;					
				}
				/* Retry if the device is not ready */
				if (mctp_ret == MCTP_RET_DEVICE_NOT_READY) {
					/* Make sure it's not timedout before continuing */
					if (timeout <
					    MCTP_DEVICE_SET_EID_TIMEOUT) {
						/* Increment the timeout */
						timeout +=
							MCTP_DEVICE_READY_DELAY;

						/* Set the discover mode as MCTP_SET_EP_REQUEST */
						discovery_mode =
							MCTP_SET_EP_REQUEST;

						/* Sleep for a while */
#if !USE_FUZZ_CTRL
						sleep(MCTP_DEVICE_READY_DELAY);
#endif
						break;
					}

					MCTP_CTRL_ERR(
						"%s: Timedout[%d] MCTP_SET_EP_RESPONSE\n",
						__func__, timeout);
#ifdef MCTP_IN_KERNEL						
						close(ctrl->sock);
#endif

					return MCTP_RET_DISCOVERY_FAILED;
				}
				
				if (g_kernel_reject_set_eid > 0) {
					kernel_binding->eid = g_kernel_reject_set_eid;
					g_kernel_reject_set_eid = 0;
				}

				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_DEBUG(
						"%s: Failed MCTP_SET_EP_RESPONSE\n",
						__func__);
						discovery_mode = MCTP_FINISH_DISCOVERY;
						break;
						//return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Reset the timeout */
				timeout = 0;
				MCTP_CTRL_INFO(
						"%s: Setting eid %d\n",
						__func__, kernel_binding->eid);

				discovery_mode = MCTP_GET_EP_UUID_REQUEST;

				break;

			case MCTP_GET_EP_UUID_REQUEST:
				/* Send the MCTP_GET_EP_UUID_REQUEST */

				MCTP_CTRL_DEBUG(
					"%s: Send UUID Request for EID: 0x%x\n",
					__func__, kernel_binding->eid);

				mctp_ret =
					mctp_kernel_get_endpoint_uuid_send_request(
						ctrl->sock,
						kernel_binding->eid);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_GET_EP_UUID_REQUEST\n",
						__func__);
#ifdef MCTP_IN_KERNEL						
						close(ctrl->sock);
#endif

					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_GET_EP_UUID_RESPONSE;

				break;

			case MCTP_GET_EP_UUID_RESPONSE:

				if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
					MCTP_CTRL_ERR(
						"%s: MCTP_GET_EP_UUID_RESPONSE Failed EID: %d\n",
						__func__, kernel_binding->eid);
				} else {
					/* Process the MCTP_GET_EP_UUID_RESPONSE */
					mctp_ret =
						mctp_kernel_get_endpoint_uuid_response(
							kernel_binding->eid,
							mctp_resp_msg,
							resp_msg_len);

					if (mctp_ret !=
					    MCTP_RET_REQUEST_SUCCESS) {
						MCTP_CTRL_ERR(
							"%s: MCTP_GET_EP_UUID_RESPONSE Failed\n",
							__func__);
					}
					/* Free Rx packet */
					free(mctp_resp_msg);
					mctp_resp_msg = NULL;
					free(mctp_hdr_msg);
					mctp_hdr_msg = NULL;					
				}

				discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;

				break;

			case MCTP_GET_MSG_TYPE_REQUEST:

				MCTP_CTRL_DEBUG(
					"%s: Send Get Msg type Request for EID: 0x%x\n",
					__func__, kernel_binding->eid);

				mctp_ret = mctp_kernel_get_msg_type_request(
					ctrl->sock, kernel_binding->eid);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_CTRL_ERR(
						"%s: Failed MCTP_GET_MSG_TYPE_REQUEST\n",
						__func__);
#ifdef MCTP_IN_KERNEL						
						close(ctrl->sock);
#endif

					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_GET_MSG_TYPE_RESPONSE;

				break;

			case MCTP_GET_MSG_TYPE_RESPONSE:

				if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
					MCTP_CTRL_ERR(
						"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed EID: %d\n",
						__func__, kernel_binding->eid);
				} else {
					/* Process the MCTP_GET_MSG_TYPE_RESPONSE */
					mctp_ret =
						mctp_kernel_get_msg_type_response(
							kernel_binding->eid,
							mctp_resp_msg,
							resp_msg_len,
							kernel_binding->binding,
							kernel_binding->own_eid,
							kernel_binding->interface_name,
							if_nametoindex(kernel_binding->interface_name),
							kernel_binding->network);

					/* Free Rx packet */
					free(mctp_resp_msg);
					mctp_resp_msg = NULL;
					free(mctp_hdr_msg);
					mctp_hdr_msg = NULL;					

					if (mctp_ret !=
					    MCTP_RET_REQUEST_SUCCESS) {
						MCTP_CTRL_ERR(
							"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed\n",
							__func__);
					}
				}

#if 0
				/* Do procedure again if next EID is available */
				number_of_eid++;
				if (number_of_eid < cmd->dest_eid_tab_len) {
					MCTP_CTRL_DEBUG(
						"%s: Set EID for next endpoint from pool.\n",
						__func__);
					discovery_mode = MCTP_SET_EP_REQUEST;
					break;
				}
#endif
				/* Finally update the global mctp_discovered_endpoints */
				MCTP_CTRL_DEBUG(
					"%s: Completed discovery process..\n",
					__func__);
				discovery_mode = MCTP_FINISH_DISCOVERY;

				break;

			default:
				MCTP_CTRL_ERR("%s: Wrong discovery mode %d \n",
					      __func__, discovery_mode);
				// assert(0);
				break;
			}

		} while (discovery_mode != MCTP_FINISH_DISCOVERY);
#ifdef MCTP_IN_KERNEL						
						close(ctrl->sock);
#endif

	}

	daemon_mode = true;

	/* Display all UUID details */
	MCTP_CTRL_DEBUG("%s: Obtained UUID entries\n", __func__);
	mctp_uuid_display();

	/* Display all message type details */
	MCTP_CTRL_DEBUG("%s: Obtained Message type entries\n", __func__);
	mctp_msg_types_display();

	return MCTP_RET_DISCOVERY_SUCCESS;
}
