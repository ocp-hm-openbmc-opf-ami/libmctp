#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>

#include "libmctp-cmds.h"
#include "libmctp-astpcie.h"
#include "libmctp-astspi.h"
#include "libmctp-log.h"

#include "mctp-encode.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-discovery-common.h"
#include "mctp-discovery.h"
#include "mctp-discovery-endpoint.h"
#include "mctp-ctrl.h"
#include "dbus_log_event.h"
#include "compiler.h"
#include "uuid/uuid.h"
#include "mctp-utils.h"
#ifdef MCTP_IN_KERNEL
#include "mctp-discovery-kernel.h"
#endif

extern const char *phy_transport_binding_to_string(uint8_t id);

extern uint8_t g_eid_pool_size;
extern uint8_t g_eid_pool_start;
extern mctp_routing_table_t *g_routing_table_entries;
extern const uint8_t MCTP_ROUTING_ENTRY_START;

/* Send function for Allocate Endpoint ID */
mctp_ret_codes_t mctp_requester_alloc_eid_send_request(
	int sock_fd, mctp_binding_ids_t bind_id, mctp_eid_t assigned_eid,
	mctp_ctrl_cmd_set_eid_op op, uint8_t eid_count, uint8_t eid_start, uint16_t remote_id, mctp_eid_t pci_own_eid)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_alloc_eid set_eid_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	/* Set destination EID as NULL */
	mctp_eid_t dest_eid = assigned_eid;;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;
#ifndef MCTP_IN_KERNEL	
	struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, 0};
 #else
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, MCTP_TAG_OWNER};
 #endif

	/* Set private binding */
	if (MCTP_BINDING_PCIE == bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_BY_ID;
		pvt_binding_pcie.remote_id = remote_id;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	} else if (MCTP_BINDING_SPI == bind_id) {
		memset(&pvt_binding_spi, 0, sizeof(pvt_binding_spi));
		pvt_binding = &pvt_binding_spi;
		binding_size = sizeof(pvt_binding_spi);
	}

	/* Allocate Endpoint ID's message */
	req_ret = mctp_encode_ctrl_cmd_alloc_eid(&set_eid_req,
			(mctp_ctrl_cmd_alloc_eid_op)op, eid_count, eid_start);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet preparation failed\n", __func__);
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
	MCTP_SYS_TRACE("%s: Sending EP request\n", __func__);
    mctp_ret = mctp_msg_client_with_binding_send(
        dest_eid, sock_fd, (const uint8_t *)&ep_req,
        sizeof(struct mctp_ctrl_cmd_alloc_eid), (uint8_t*)&mctp_hdr, &bind_id,
        pvt_binding, binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Set Endpoint ID */
int mctp_requester_set_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len,
			      uint8_t *eid, size_t *eid_count)
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
		MCTP_SYS_ERR("%s: Packet parsing failed\n", __func__);

		/* Check wheteher device is ready or not */
		if (set_eid_resp->completion_code ==
		    MCTP_CONTROL_MSG_STATUS_ERROR_NOT_READY) {
			MCTP_SYS_DEBUG(
				"%s: Device [eid: %d] is not ready yet..\n",
				__func__, set_eid_resp->eid_set);
			return MCTP_RET_DEVICE_NOT_READY;
		}

		return MCTP_RET_ENCODE_FAILED;
	}

	*eid = set_eid_resp->eid_set;

	/* Check whether the EID is accepted by the device or not */
	if (set_eid_resp->status & MCTP_SETEID_ASSIGN_STATUS_REJECTED) {
		MCTP_SYS_DEBUG(
			"%s: Set Endpoint id: 0x%x, Status:0x%x (Rejected by the device)\n",
			__func__, set_eid_resp->status, set_eid_resp->eid_set);

	} else {
		MCTP_SYS_DEBUG(
			"%s: Set Endpoint id: 0x%x (Accepted by the device)\n",
			__func__, set_eid_resp->eid_set);
	}

	/* Check whether the device requires EID pool allocation or not */
	if (set_eid_resp->status & MCTP_SETEID_ALLOC_STATUS_EID_POOL_REQ) {
		MCTP_SYS_DEBUG(
			"%s: Endpoint require EID pool allocation: 0x%x (status)\n",
			__func__, set_eid_resp->status);

		/* update the eid_count pointer */
		*eid_count = set_eid_resp->eid_pool_size;

		MCTP_SYS_DEBUG("%s: g_eid_pool_size: 0x%x\n", __func__,
				g_eid_pool_size);

	} else {
		MCTP_SYS_DEBUG(
			"%s: Endpoint doesn't require EID pool allocation: 0x%x (status)\n",
			__func__, set_eid_resp->status);

		/* Reset the EID pool size */
		g_eid_pool_size = 0;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Set Endpoint ID */
mctp_ret_codes_t mctp_requester_set_eid_send_request(int sock_fd,
					   mctp_binding_ids_t bind_id,
					   mctp_ctrl_cmd_set_eid_op op,
					   uint8_t eid,
					   mctp_eid_t pci_own_eid,
					   int g_target_bdf)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;

	struct mctp_ctrl_cmd_set_eid set_eid_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	/* Set destination EID as NULL */
	mctp_eid_t dest_eid = MCTP_EID_NULL;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	size_t binding_size = 0;
#ifndef MCTP_IN_KERNEL	
	struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, 0};
 #else
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, MCTP_TAG_OWNER};
 #endif

	/* Set private binding */
	if (MCTP_BINDING_PCIE == bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_BY_ID;
		pvt_binding_pcie.remote_id = g_target_bdf;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	}

	/* Encode Set Endpoint ID message */
	req_ret = mctp_encode_ctrl_cmd_set_eid(&set_eid_req, op, eid);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet preparation failed\n", __func__);
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
	MCTP_SYS_TRACE("%s: Sending EP request\n", __func__);
    mctp_ret = mctp_msg_client_with_binding_send(
        dest_eid, sock_fd, (const uint8_t *)&ep_req,
        sizeof(struct mctp_ctrl_cmd_set_eid), (uint8_t*)&mctp_hdr, &bind_id,
        pvt_binding, binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Allocate Endpoint ID */
int mctp_requester_alloc_eid_get_response(uint8_t *mctp_resp_msg, size_t resp_msg_len, mctp_eid_t *eid_pool_start, size_t * eid_pool_size)
{
	bool req_ret;
	struct mctp_ctrl_resp_alloc_eid *alloc_eid_resp;

	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
			    "MCTP_ALLOCATE_EP_ID_RESPONSE",
			    resp_msg_len -
				    sizeof(struct mctp_ctrl_cmd_msg_hdr));

	/* Copy the Rx packet header */
	alloc_eid_resp = (struct mctp_ctrl_resp_alloc_eid *)mctp_resp_msg;

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_alloc_eid(alloc_eid_resp);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Check whether allocation was accepted or not */
	if (alloc_eid_resp->alloc_status == MCTP_ALLOC_EID_REJECTED) {
		MCTP_SYS_ERR(
			"%s: Alloc Endpoint ID rejected/already allocated by another bus owner\n",
			__func__);
	}

	/* Get EID pool size and the EID start */
	*eid_pool_size = alloc_eid_resp->eid_pool_size;
	*eid_pool_start = alloc_eid_resp->eid_start;

	MCTP_SYS_DEBUG("%s: g_eid_pool_size: %d, eid_start: %d\n", __func__,
			g_eid_pool_size, g_eid_pool_start);

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get routing table */
int mctp_requester_get_routing_table_get_response(mctp_ctrl_t *ctrl, mctp_eid_t eid, mctp_binding_ids_t bind_id,
					uint8_t *mctp_resp_msg,
					size_t resp_msg_len,
					bool remove_duplicates,
                    mctp_eid_t g_pci_own_eid,
					uint8_t *entry_hdl)
{
	bool req_ret;
	struct mctp_ctrl_resp_get_routing_table *routing_table;
	int ret;
	char arg[REDFISH_ARG_LEN] = { 0 };

	(void)eid;

	MCTP_SYS_TRACE("%s: Get EP reesponse\n", __func__);

	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
			    "MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE",
			    resp_msg_len -
				    sizeof(struct mctp_ctrl_cmd_msg_hdr));

	routing_table =
		(struct mctp_ctrl_resp_get_routing_table *)mctp_resp_msg;

	/* Parse the endpoint discovery message */
	req_ret = mctp_decode_resp_get_routing_table(routing_table);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet parsing failed\n", __func__);

		/* Check wheteher device is ready or not */
		if (routing_table->completion_code ==
		    MCTP_CONTROL_MSG_STATUS_ERROR_NOT_READY) {
			MCTP_SYS_DEBUG("%s: Device is not ready yet..\n",
					__func__);
			return MCTP_RET_DEVICE_NOT_READY;
		}
		return MCTP_RET_ENCODE_FAILED;
	}

	MCTP_SYS_DEBUG("%s: Next entry handle: %d, Number of entries: %d\n",
			__func__, routing_table->next_entry_handle,
			routing_table->number_of_entries);

	*entry_hdl = routing_table->next_entry_handle;

	/* Check if the routing table exist */
	if (routing_table->number_of_entries) {
		int16_t entries = routing_table->number_of_entries;
		struct get_routing_table_entry * next_routing_table_entry = (struct get_routing_table_entry *) ((uint8_t*) mctp_resp_msg + 
					sizeof(struct mctp_ctrl_resp_get_routing_table));
		while (entries-- > 0)
		{
			struct get_routing_table_entry routing_table_entry;

			/* Copy the routing table entries to local routing table */
			memcpy(&routing_table_entry, next_routing_table_entry,
				sizeof(struct get_routing_table_entry) - (next_routing_table_entry->phys_address_size % 2));

			next_routing_table_entry = (struct get_routing_table_entry *) ((uint8_t*) next_routing_table_entry +
				sizeof(struct get_routing_table_entry) - next_routing_table_entry->phys_address_size % 2);

			if (routing_table_entry.phys_transport_binding_id != bind_id && 
			    routing_table_entry.phys_transport_binding_id != MCTP_BINDING_VDM) {
			        continue;
			}

			/* Dont add the entry to the routing table if the EID is it's own */
			if (routing_table_entry.starting_eid == g_pci_own_eid) {
				MCTP_SYS_DEBUG(
					"%s: Found it's own eid: [%d] in the Routing table\n",
					__func__, routing_table_entry.starting_eid);
			} else {
				/* Check transport binding id and filter out the unknown binding */
				if (strncmp(phy_transport_binding_to_string(
							routing_table_entry
								.phys_transport_binding_id),
						"Unknown", 7) != 0) {

					/* Add the entry to a linked list */
					ret = mctp_routing_entry_add(
						&routing_table_entry);
					if (ret < 0) {
						MCTP_SYS_ERR(
							"%s: Failed to update global routing table..\n",
							__func__);
						return MCTP_RET_REQUEST_FAILED;
					}
#ifdef MCTP_IN_KERNEL
					/* Setup kernel-specific routing operations only for bridge entries */
					/* Check if entry type indicates a bridge (bits [7:6] = 10b or 11b) */
					uint8_t entry_type_bits = (routing_table_entry.entry_type >> 6) & 0x3;
					if (entry_type_bits == 0x2 || entry_type_bits == 0x3) {
						MCTP_SYS_DEBUG("%s: Bridge entry detected (entry_type=0x%02x), setting up kernel routing for EID %d\n",
								__func__, routing_table_entry.entry_type, routing_table_entry.starting_eid);
						if (mctp_kernel_setup_routing_entry(&routing_table_entry) < 0) {
							MCTP_SYS_ERR(
								"%s: Failed to setup kernel routing entry for bridge EID %d\n",
								__func__, routing_table_entry.starting_eid);
						}
					} else {
						MCTP_SYS_DEBUG("%s: Non-bridge entry (entry_type=0x%02x), skipping kernel routing setup for EID %d\n",
								__func__, routing_table_entry.entry_type, routing_table_entry.starting_eid);
					}
#endif
					/* Print the routing table entry */
					mctp_print_routing_table_entry(
						g_routing_table_entries->id,
						&routing_table_entry);

					/* Length of the Routing table */
					MCTP_SYS_DEBUG(
						"%s: EID: 0x%x, Routing table length: %d\n",
						__func__,
						routing_table_entry.starting_eid,
						g_eid_pool_size);
				} else {
					MCTP_SYS_DEBUG(
						"%s: EID: 0x%x: No valid medium type\n",
						__func__,
						routing_table_entry.starting_eid);

					snprintf(
						arg, sizeof(arg),
						"Endpoint Identifer %d with no valid transport medium type",
						routing_table_entry.starting_eid);
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service", arg,
						EVT_CRITICAL, "Contact NVIDIA");
				}
			}
		}

		/* Check if the next routing table exist.. */
		if (routing_table->next_entry_handle != 0xFF) {
			
			MCTP_SYS_DEBUG("%s: Next routing entry found %d\n",
					__func__,
					routing_table->next_entry_handle);
			return MCTP_RET_ROUTING_TABLE_FOUND;
		} else {
			
			MCTP_SYS_DEBUG("%s: No more routing entries %d\n",
					__func__,
					routing_table->next_entry_handle);
		}
	}

	// Remove any duplicate EIDs
	if (remove_duplicates) {
		MCTP_SYS_DEBUG("Checking Routing Table...\n");
		mctp_routing_table_t *routing_entry = g_routing_table_entries;
		while (routing_entry != NULL) {
			uint8_t current_eid = routing_entry->routing_table.starting_eid;
			uint8_t current_binding_id = routing_entry->routing_table.phys_transport_binding_id;
			uint8_t current_entry_type = routing_entry->routing_table.entry_type;
			mctp_routing_table_t *walker = routing_entry->next;
			mctp_routing_table_t *walkedFrom = routing_entry;
			while (walker != NULL) {
				if (walker->routing_table.starting_eid == current_eid &&
					walker->routing_table.phys_transport_binding_id == current_binding_id &&
					walker->routing_table.entry_type == current_entry_type) {
					MCTP_SYS_DEBUG("WARNING: EID %d was duplicated in routing table. Removing duplicate entry.\n", current_eid);
					mctp_routing_table_t *dup_entry = walker;
					walkedFrom->next = walker->next;
					walker = walker->next;
					free(dup_entry);
				} else {
					walkedFrom = walker;
					walker = walker->next;
				}
			}
			routing_entry = routing_entry->next;
		}
	}


	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get routing table */
mctp_ret_codes_t mctp_requester_get_routing_table_send_request(int sock_fd,
						     mctp_binding_ids_t bind_id,
						     mctp_eid_t dest_eid,
						     uint8_t entry_handle,
                             mctp_eid_t pci_own_eid,
                             uint16_t remote_id)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_routing_table get_routing_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;
#ifndef MCTP_IN_KERNEL	
	struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, 0};
 #else
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, MCTP_TAG_OWNER};
 #endif

	/* Set private binding */
	if (MCTP_BINDING_PCIE == bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_BY_ID;
		pvt_binding_pcie.remote_id = remote_id;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	} else if (MCTP_BINDING_SPI == bind_id) {
		memset(&pvt_binding_spi, 0, sizeof(pvt_binding_spi));
		pvt_binding = &pvt_binding_spi;
		binding_size = sizeof(pvt_binding_spi);
	}

	/* Get routing table request message */
	req_ret = mctp_encode_ctrl_cmd_get_routing_table(
		&get_routing_req, entry_handle);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

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
		sizeof(struct mctp_ctrl_cmd_get_routing_table), (uint8_t*)&mctp_hdr, &bind_id,
		pvt_binding, binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get UUID */
mctp_ret_codes_t mctp_requester_get_endpoint_uuid_send_request(int sock_fd,
						     mctp_binding_ids_t bind_id,
						     mctp_eid_t dest_eid,
                             mctp_eid_t pci_own_eid,
                             uint16_t remote_id)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_uuid uuid_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;
#ifndef MCTP_IN_KERNEL	
	struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, 0};
 #else
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, MCTP_TAG_OWNER};
 #endif

	/* Set private binding */
	if (MCTP_BINDING_PCIE == bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_BY_ID;
		pvt_binding_pcie.remote_id = remote_id;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	} else if (MCTP_BINDING_SPI == bind_id) {
		memset(&pvt_binding_spi, 0, sizeof(pvt_binding_spi));
		pvt_binding = &pvt_binding_spi;
		binding_size = sizeof(pvt_binding_spi);
	}

	/* Encode for Get Endpoint UUID message */
	req_ret = mctp_encode_ctrl_cmd_get_uuid(&uuid_req);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet preparation failed\n", __func__);
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
		sizeof(struct mctp_ctrl_cmd_get_uuid), (uint8_t*)&mctp_hdr, &bind_id, pvt_binding,
		binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get VDM */
mctp_ret_codes_t mctp_requester_get_vdm_support_send_request(int sock_fd,
						     mctp_binding_ids_t bind_id,
						     mctp_eid_t dest_eid,
						     mctp_eid_t pci_own_eid,
						     uint16_t remote_id,
						     uint8_t v_id_set_selector)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_vdm_support vdm_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;
#ifndef MCTP_IN_KERNEL	
	struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, 0};
 #else
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, MCTP_TAG_OWNER};
 #endif

	/* Set private binding */
	if (MCTP_BINDING_PCIE == bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_BY_ID;
		pvt_binding_pcie.remote_id = remote_id;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	} else if (MCTP_BINDING_SPI == bind_id) {
		memset(&pvt_binding_spi, 0, sizeof(pvt_binding_spi));
		pvt_binding = &pvt_binding_spi;
		binding_size = sizeof(pvt_binding_spi);
	}

	/* Encode for Get Endpoint VDM support message */
	req_ret = mctp_encode_ctrl_cmd_get_vdm_support(&vdm_req,v_id_set_selector);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_get_vdm_support) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &vdm_req, sizeof(struct mctp_ctrl_cmd_get_vdm_support));

	mctp_print_req_msg(&ep_req, "MCTP_GET_EP_VDM_SUPPORT_REQUEST", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_get_vdm_support), (uint8_t*)&mctp_hdr, &bind_id, pvt_binding,
		binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get vendor message tyep support */
mctp_ret_codes_t mctp_requester_get_vdm_support_send_response(
                             mctp_eid_t eid,
                             uint8_t *mctp_resp_msg,
                             size_t resp_msg_len,
                             uint8_t *v_id_set_selector
                             )
{
    bool req_ret;
    struct mctp_pci_ctrl_resp_get_vdm_support vdm_resp = { 0 };
    mctp_vdm_table_t vdm_table = { 0 };
    vendor_id_set_cmd_type_node_t new_cmd_type_node = { 0 };
    struct mctp_ctrl_resp *resp_msg = (struct mctp_ctrl_resp *)mctp_resp_msg;
    int msg_len = resp_msg_len - sizeof(struct mctp_ctrl_cmd_msg_hdr);
    int ret;

    /* Trace the Rx message */
    mctp_print_resp_msg(resp_msg, "MCTP_GET_EP_VDM_SUPPORT_RESPONSE", msg_len);

    vdm_resp.ctrl_hdr = resp_msg->hdr;
    vdm_resp.completion_code = resp_msg->completion_code;
    vdm_resp.vendor_id_set_selector = resp_msg->data[0];
    vdm_resp.vendor_id_format = resp_msg->data[1];
    vdm_resp.vendor_id_data = resp_msg->data[2] << 8 | resp_msg->data[3];
    vdm_resp.command_set_type = resp_msg->data[4] << 8 | resp_msg->data[5];

    /* Parse the VDM response message */
    req_ret = mctp_decode_ctrl_cmd_get_vdm_support(&vdm_resp);
    if (req_ret == false) {
        MCTP_SYS_ERR("%s: Packet parsing failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }

    *v_id_set_selector = vdm_resp.vendor_id_set_selector;

    /* Update VDM private params to export to upper layer */
    vdm_table.eid = eid;
    vdm_table.vendor_id = vdm_resp.vendor_id_data;
    vdm_table.v_id_set_selector = *v_id_set_selector;
    vdm_table.vendor_id_set_cmd_type = NULL;
    vdm_table.next = NULL;

    new_cmd_type_node.data = vdm_resp.command_set_type;
    new_cmd_type_node.next = NULL;

    /* Create a new VDM entry and add to list */
    ret = mctp_vdm_entry_add(&vdm_table, &new_cmd_type_node);
    if (ret < 0) {
        MCTP_SYS_ERR("%s: Failed to update global VDM table..\n", __func__);
        return MCTP_RET_REQUEST_FAILED;
    }

    if(*v_id_set_selector != 0xFF) {
        MCTP_SYS_DEBUG("%s: Next selector found %d\n", __func__, *v_id_set_selector);
        return MCTP_RET_SET_SELECTOR_FOUND;
    } else {
        MCTP_SYS_DEBUG("%s: No more selector %d\n", __func__, *v_id_set_selector);
    }

    return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get Messgae types */
mctp_ret_codes_t mctp_requester_get_msg_type_send_request(int sock_fd,
					   mctp_binding_ids_t bind_id,
					   mctp_eid_t dest_eid,
                             mctp_eid_t pci_own_eid,
                             uint16_t remote_id)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_get_msg_type_support msg_type_req;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;
#ifndef MCTP_IN_KERNEL	
	struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, 0};
 #else
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, MCTP_TAG_OWNER};
 #endif

	/* Set private binding */
	if (MCTP_BINDING_PCIE == bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_BY_ID;
		pvt_binding_pcie.remote_id = remote_id;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	} else if (MCTP_BINDING_SPI == bind_id) {
		memset(&pvt_binding_spi, 0, sizeof(pvt_binding_spi));
		pvt_binding = &pvt_binding_spi;
		binding_size = sizeof(pvt_binding_spi);
	}

	/* Encode for Get Endpoint UUID message */
	req_ret = mctp_encode_ctrl_cmd_get_msg_type_support(&msg_type_req);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet preparation failed\n", __func__);
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
	MCTP_SYS_TRACE("%s: Sending EP request\n", __func__);
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_req,
		sizeof(struct mctp_ctrl_cmd_get_msg_type_support), (uint8_t*)&mctp_hdr, &bind_id,
		pvt_binding, binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Prepare for Endpoint discovery */
mctp_ret_codes_t
mctp_requester_prepare_ep_discovery_send_request(
                             int sock_fd, 
                             mctp_binding_ids_t bind_id, 
                             mctp_eid_t pci_own_eid, 
                             int g_target_bdf
							 )
{
    bool req_ret;
    mctp_requester_rc_t mctp_ret;
    struct mctp_ctrl_cmd_prepare_ep_discovery prep_ep_discovery;
    struct mctp_ctrl_req ep_discovery_req;
    size_t msg_len;
    mctp_eid_t dest_eid = MCTP_EID_BROADCAST;
    void *pvt_binding = NULL;
    struct mctp_astpcie_pkt_private pvt_binding_pcie;
    size_t binding_size = 0;
#ifndef MCTP_IN_KERNEL	
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, 0};
 #else
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, MCTP_TAG_OWNER};
 #endif
 
    /* Set private binding */
    if (MCTP_BINDING_PCIE == bind_id) {
        pvt_binding_pcie.routing = PCIE_BROADCAST_FROM_RC;
        pvt_binding_pcie.remote_id = g_target_bdf;
        pvt_binding = &pvt_binding_pcie;
        binding_size = sizeof(pvt_binding_pcie);
    }
 
    /* Prepare the endpoint discovery message */
    req_ret = mctp_encode_ctrl_cmd_prepare_ep_discovery(&prep_ep_discovery);
    if (req_ret == false) {
        MCTP_SYS_ERR("%s: Packet preparation failed\n", __func__);
        return MCTP_RET_ENCODE_FAILED;
    }
 
    /* Get the message length */
    msg_len = sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery) -
          sizeof(struct mctp_ctrl_cmd_msg_hdr);
 
    MCTP_SYS_DEBUG("%s: message length: %zu\n", __func__, msg_len);
 
    /* Initialize the buffers */
    memset(&ep_discovery_req, 0, sizeof(ep_discovery_req));
 
    /* Copy to Tx packet */
    memcpy(&ep_discovery_req, &prep_ep_discovery,
           sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery));
 
    mctp_print_req_msg(&ep_discovery_req,
               "MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST", msg_len);
 
    /* Send the request message over socket */
    MCTP_SYS_TRACE("%s: Sending EP request\n", __func__);
    mctp_ret = mctp_msg_client_with_binding_send(
        dest_eid, sock_fd, (const uint8_t *)&ep_discovery_req,
        sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery), (uint8_t*)&mctp_hdr, &bind_id,
        pvt_binding, binding_size);
 
    if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
        MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
        return MCTP_RET_REQUEST_FAILED;
    }
 
    return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Endpoint discovery */
mctp_ret_codes_t mctp_requester_ep_discovery_send_request(int sock_fd,
						mctp_binding_ids_t bind_id,
						mctp_eid_t pci_own_eid, 
						int g_target_bdf)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_ep_discovery ep_discovery;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	/* Set destination EID as broadcast */
	mctp_eid_t dest_eid = MCTP_EID_BROADCAST;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	size_t binding_size = 0;
#ifndef MCTP_IN_KERNEL	
	struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, 0};
 #else
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, MCTP_TAG_OWNER};
 #endif

	/* Set private binding */
	if (MCTP_BINDING_PCIE == bind_id) {
		pvt_binding_pcie.routing = PCIE_BROADCAST_FROM_RC;
		pvt_binding_pcie.remote_id = g_target_bdf;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	}

	/* Prepare the endpoint discovery message */
	req_ret = mctp_encode_ctrl_cmd_ep_discovery(&ep_discovery);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_ep_discovery) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	MCTP_SYS_DEBUG("%s: message length: %zu\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &ep_discovery,
	       sizeof(struct mctp_ctrl_cmd_ep_discovery));

	mctp_print_req_msg(&ep_req,
               "MCTP_EP_DISCOVERY_REQUEST", msg_len);

	/* Send the request message over socket */
	MCTP_SYS_TRACE("%s: Sending EP request\n", __func__);
    mctp_ret = mctp_msg_client_with_binding_send(
        dest_eid, sock_fd, (const uint8_t *)&ep_req,
        sizeof(struct mctp_ctrl_cmd_ep_discovery), (uint8_t*)&mctp_hdr, &bind_id,
        pvt_binding, binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
	}

	return MCTP_RET_REQUEST_SUCCESS;
}


/* Send function for Endpoint discovery */
mctp_ret_codes_t mctp_requester_discovery_notify_send_request(int sock_fd,
						mctp_binding_ids_t bind_id,
						mctp_eid_t pci_own_eid, 
						int g_target_bdf)
{
	bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_cmd_discovery_notify ep_discovery;
	struct mctp_ctrl_req ep_req;
	size_t msg_len;
	/* Set destination EID as broadcast */
	mctp_eid_t dest_eid = MCTP_EID_NULL;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	size_t binding_size = 0;
#ifndef MCTP_IN_KERNEL	
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, 0};
 #else
    struct mctp_hdr mctp_hdr = {1, dest_eid, pci_own_eid, MCTP_TAG_OWNER};
 #endif

	/* Set private binding */
	if (MCTP_BINDING_PCIE == bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_TO_RC;
		pvt_binding_pcie.remote_id = g_target_bdf;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	}

	/* Prepare the endpoint discovery message */
	req_ret = mctp_encode_ctrl_cmd_discovery_notify(&ep_discovery);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet preparation failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_cmd_discovery_notify) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	MCTP_SYS_DEBUG("%s: message length: %zu\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_req, 0, sizeof(ep_req));

	/* Copy to Tx packet */
	memcpy(&ep_req, &ep_discovery,
	       sizeof(struct mctp_ctrl_cmd_discovery_notify));

	mctp_print_req_msg(&ep_req,
               "MCTP_DISCOVERY_NOTIFY_REQUEST", msg_len);

	/* Send the request message over socket */
	MCTP_SYS_TRACE("%s: Sending EP request\n", __func__);
    mctp_ret = mctp_msg_client_with_binding_send(
        dest_eid, sock_fd, (const uint8_t *)&ep_req,
        sizeof(struct mctp_ctrl_cmd_discovery_notify), (uint8_t*)&mctp_hdr, &bind_id,
        pvt_binding, binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
	}

	return MCTP_RET_REQUEST_SUCCESS;
}