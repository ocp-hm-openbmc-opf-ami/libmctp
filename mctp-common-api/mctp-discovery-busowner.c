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
#include "mctp-discovery-busowner.h"
#include "mctp-ctrl.h"
#include "dbus_log_event.h"
#include "compiler.h"
#include "uuid/uuid.h"
#include "mctp-requester.h"
#include "mctp-responder.h"
#include "time.h"
#include "mctp-ext-sdbus.h"
#include "mctp-utils.h"


extern const char *phy_transport_binding_to_string(uint8_t id);

extern uint8_t g_eid_pool_size;
extern uint8_t g_eid_pool_start;
extern mctp_routing_table_t *g_routing_table_entries;
extern const uint8_t MCTP_ROUTING_ENTRY_START;

/* PCIe target bdf */
static int g_target_bdf = 0;
/* The EIDs and pool start information would be obtaind from commandline */
static uint8_t g_pci_bridge_eid, g_pci_own_eid, g_pci_bridge_pool_start;
static uint8_t g_endpoint_dicovered = 0;
static bool daemon_mode = false;
static uint16_t g_remote_id;

#define MAX_RETRY_PREPARE_DISCOVERY 3
#define MAX_DISCOVERY_COMMAND_TIME_OUT  999
#define MAX_DISCOVERY_RETRY_PERIOD 60

/* MCTP discovery response receive routine */
static mctp_ret_codes_t mctp_discover_response(mctp_ctrl_t *ctrl,
					       mctp_discovery_mode mode,
					       mctp_eid_t *eid,
					       uint8_t **mctp_resp_msg,
					       size_t *mctp_resp_len,
   						   uint8_t **mctp_hdr_msg)
{
	int sock = ctrl->sock;
	mctp_requester_rc_t mctp_ret;
	//char *device_name = "PCIe Device Enumeration Service";
    
	/* Ignore request commands */
	switch (mode) {
	case MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST:
	case MCTP_EP_DISCOVERY_REQUEST:
	case MCTP_SET_EP_REQUEST:
	case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:
	case MCTP_GET_EP_UUID_REQUEST:
	case MCTP_GET_EP_VDM_SUPPORT_REQUEST:
	case MCTP_GET_MSG_TYPE_REQUEST:
		return MCTP_RET_REQUEST_SUCCESS;

	default:
		break;
	}

	switch (mode) {
	case MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE:
	case MCTP_EP_DISCOVERY_RESPONSE:
	case MCTP_SET_EP_RESPONSE:
	case MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE:
	case MCTP_GET_EP_UUID_RESPONSE:
	case MCTP_GET_EP_VDM_SUPPORT_RESPONSE:
	case MCTP_GET_MSG_TYPE_RESPONSE:

		/* Receive MCTP packets */
		mctp_ret = mctp_client_sync_recv(eid, sock, mctp_resp_msg,
					    mctp_resp_len, mctp_hdr_msg, &g_remote_id);

		if (mctp_ret == MCTP_REQUESTER_TIMEOUT) {
			if (mode == MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE) {
				/* Get routing table commands has their own timeout */
				//doLog(ctrl->bus, device_name,
				//      "No valid routing table", EVT_CRITICAL,
				//      "Reset the baseboard");
				return MCTP_RET_REQUEST_FAILED;
			}
			//doLog(ctrl->bus, device_name, "Discovery Timed Out",
			//      EVT_CRITICAL, "Reset the baseboard");

			return MCTP_RET_REQUEST_FAILED;
		} else if (mctp_ret == MCTP_REQUESTER_RECV_FAIL ||
			   mctp_ret == MCTP_REQUESTER_INVALID_RECV_LEN) {
			if (mode == MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE) {
				/* Get routing table commands has their error handling */
				return MCTP_RET_REQUEST_FAILED;
			}
			MCTP_SYS_DEBUG("%s: Failed to received message %d\n",
				      __func__, mctp_ret);

			//doLog(ctrl->bus, device_name, "Failed to discover",
			//      EVT_CRITICAL, "Reset the baseboard");
			return MCTP_RET_REQUEST_FAILED;
		}
		break;

	default:
		MCTP_SYS_DEBUG("%s: Unknown discovery mode: %d\n", __func__,
				mode);
		break;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Routine to Discover the endpoint devices */
mctp_ret_codes_t mctp_busowner_mode_discover_endpoints(const mctp_cmdline_args_t *cmd,
					 mctp_ctrl_t *ctrl)
{
	static int discovery_mode = MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST;

	if(g_endpoint_dicovered || discovery_mode != MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST){
		discovery_mode = MCTP_EP_DISCOVERY_REQUEST;
		MCTP_SYS_DEBUG("%s Start busowner mode partial discover \n", __func__);
	}

	mctp_ret_codes_t mctp_ret;
	uint8_t entry_hdl = MCTP_ROUTING_ENTRY_START;
	uint8_t v_id_set_selector = 0;
	uint8_t *mctp_resp_msg = NULL;
	uint8_t *mctp_hdr_msg = NULL;
	size_t resp_msg_len;
	int timeout = 0;
	mctp_routing_table_t *routing_entry = NULL;
	mctp_binding_ids_t bind_id = MCTP_BINDING_PCIE;
	uint8_t eid = 0, eid_start = 0;
	/* Update Target BDF */
	g_target_bdf = mctp_ctrl_get_target_bdf(cmd);
	int64_t t_start, t_end;
	int retry_discovery = 0;
	
	/* Update the EID lists */
	if (!daemon_mode) {
#ifdef MCTP_IN_KERNEL
       uint8_t active_binding = ctrl->active_binding;
       g_pci_own_eid = cmd->kernel.binding[active_binding].own_eid;
       g_pci_bridge_eid = cmd->kernel.binding[active_binding].eid;
       g_pci_bridge_pool_start = cmd->kernel.binding[active_binding].eid_pool_start;
#else		
		g_pci_own_eid = cmd->pcie.own_eid;
		g_pci_bridge_eid = cmd->pcie.bridge_eid;
		g_pci_bridge_pool_start = cmd->pcie.bridge_pool_start;
#endif		
	}
	t_start = mctp_ext_millis();

	MCTP_SYS_DEBUG(
		"%s: pci_own_eid: %d, pci_bridge_eid: %d, pci_bridge_pool_start: %d\n",
		__func__, g_pci_own_eid, g_pci_bridge_eid,
		g_pci_bridge_pool_start);

	do {
		/* Wait for MCTP response */
		mctp_ret =
			mctp_discover_response(ctrl, discovery_mode, &eid,
					       &mctp_resp_msg, &resp_msg_len, &mctp_hdr_msg);

		MCTP_SYS_DEBUG("%s: mctp_discover_response mctp_ret = %d \n", __func__, mctp_ret);

		if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
			MCTP_SYS_DEBUG("%s: Failed to received message %d\n",
				      __func__, mctp_ret);

			/*
			 * Dont return failure for Get EP UUID and Messgae types
			 * as it need to fetch the next data from the routing
			 * table entries.
			 * NOTE: In general it's very unlikely we hit this
			 * scenario. If such failure occurs, then it could be
			 * either a firmware issue or some Hardware issue.
			 */
			if (discovery_mode != MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE &&
					discovery_mode != MCTP_EP_DISCOVERY_RESPONSE &&
					discovery_mode != MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE &&
					discovery_mode != MCTP_GET_EP_UUID_RESPONSE &&
					discovery_mode != MCTP_GET_EP_VDM_SUPPORT_RESPONSE &&
					discovery_mode != MCTP_GET_MSG_TYPE_RESPONSE) {
				MCTP_SYS_DEBUG(
					"%s: Unexpected failure %d, mode[%d]\n",
					__func__, mctp_ret, discovery_mode);		

				if (!g_endpoint_dicovered) {
					t_end = mctp_ext_millis();
					if((t_end - t_start) / 1000 > MAX_DISCOVERY_RETRY_PERIOD) {
						return MCTP_RET_DISCOVERY_FAILED;
					}
					continue;
				}	
			}
		} else if (discovery_mode != MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST &&
					discovery_mode != MCTP_EP_DISCOVERY_REQUEST &&
					discovery_mode != MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST &&
					discovery_mode != MCTP_GET_EP_UUID_REQUEST &&
					discovery_mode !=  MCTP_GET_EP_VDM_SUPPORT_REQUEST &&
					discovery_mode != MCTP_GET_MSG_TYPE_REQUEST) {
			//g_target_bdf = mctp_ctrl_get_target_bdf(cmd);
			mctp_ret_codes_t mctp_responder_ret = mctp_busowner_mode_ctrl_cmd_responder(ctrl, bind_id, eid, &mctp_resp_msg, &resp_msg_len, &mctp_hdr_msg);	
			switch(mctp_responder_ret)
			{
				case MCTP_RET_REQUEST_FAILED:
				case MCTP_CMD_SUCCESS:
					/* Free Rx packet */
					free(mctp_resp_msg);
					mctp_resp_msg = NULL;
					free(mctp_hdr_msg);
					mctp_hdr_msg = NULL;	
					/* End time */
					t_end = mctp_ext_millis();

					/* Check if it's timedout or not */
					if (g_endpoint_dicovered && (t_end - t_start) > MAX_DISCOVERY_COMMAND_TIME_OUT) {
						MCTP_SYS_DEBUG(
							"%s: MCTP Rx Command Timed out (waited %f seconds)\n",
							__func__,
							(float)(t_end - t_start) / 1000);
						mctp_ret = MCTP_RET_REQUEST_FAILED;
					} else {										
						continue;
					}

				case MCTP_CMD_FAILED:
				default:
					break;
			}
		}

		switch(discovery_mode) {

			case MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST:
				/* Send the prepare endpoint discovery message */
				mctp_ret = mctp_requester_prepare_ep_discovery_send_request(
					ctrl->sock, bind_id, g_pci_own_eid, g_target_bdf);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");
					MCTP_SYS_ERR(
						"%s: Failed MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}
	
				/* Wait for the endpoint discovery response */
				discovery_mode = MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE;
				t_start = mctp_ext_millis();
				break;

			case MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE:

				if (!g_endpoint_dicovered) {
					MCTP_SYS_ERR(
						"%s: Failed MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE\n",
						__func__);
					/* Wait for the endpoint discovery response */
					if (retry_discovery ++ < MAX_RETRY_PREPARE_DISCOVERY) {
						discovery_mode = MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST;
						break;
					}
				}
				discovery_mode = MCTP_EP_DISCOVERY_REQUEST;
				retry_discovery = 0;
				break;

			case MCTP_EP_DISCOVERY_REQUEST:

				/* Send the prepare endpoint message */
				mctp_ret = mctp_requester_ep_discovery_send_request(ctrl->sock,
									bind_id,
									g_pci_own_eid,
									g_target_bdf);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");

					MCTP_SYS_ERR(
						"%s: Failed MCTP_EP_DISCOVERY_REQUEST\n",
						__func__);
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode = MCTP_EP_DISCOVERY_RESPONSE;
				t_start = mctp_ext_millis();
				break;

			case MCTP_EP_DISCOVERY_RESPONSE:

				if (retry_discovery ++ < MAX_RETRY_PREPARE_DISCOVERY)
					discovery_mode = MCTP_EP_DISCOVERY_REQUEST;
				else {
					if (g_endpoint_dicovered && ctrl->update_routing_table) {
						discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;
					} else {
						discovery_mode = MCTP_FINISH_DISCOVERY;
					}
				}
				break;

			case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:

				if (entry_hdl == MCTP_ROUTING_ENTRY_START) {
					/* Get the start of Routing entry */
					routing_entry = g_routing_table_entries;
				}

				if (entry_hdl == 0xFF) {
					entry_hdl = MCTP_ROUTING_ENTRY_START;
					if (routing_entry)
						routing_entry = routing_entry -> next;				
				}

				if (entry_hdl == MCTP_ROUTING_ENTRY_START) {
					while(routing_entry != NULL)
					{
						if ((routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
					     			routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM) &&
							(GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) == MCTP_ROUTING_ENTRY_BRIDGE || 
								GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) == MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS))
							break;
						routing_entry = routing_entry->next;
					}
				}
				
				if (routing_entry) {
					/* Set the Start of EID */
					eid_start = routing_entry->routing_table
							.starting_eid;
					g_remote_id = routing_entry->routing_table.phys_address[0]<<8|routing_entry->routing_table.phys_address[1];
				} else {
					/* Get the start of Routing entry */
					routing_entry = g_routing_table_entries;
					while(routing_entry != NULL)
					{
						if ((routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
					     			routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM) &&
								GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) != MCTP_ROUTING_ENTRY_ENDPOINTS)
							break;
						routing_entry = routing_entry->next;
					}

					/* Next step is to Get Endpoint UUID request */
					discovery_mode = MCTP_GET_EP_UUID_REQUEST;
					break;
				}

				/* Send the MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
				mctp_ret = mctp_requester_get_routing_table_send_request(
					ctrl->sock, bind_id, eid_start, entry_hdl, g_pci_own_eid, g_remote_id);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_SYS_ERR(
						"%s: Failed MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST\n",
						__func__);
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"No valid routing table", EVT_CRITICAL,
						"Reset the baseboard");
					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Wait for the endpoint response */
				discovery_mode =
					MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE;

				/* Start time */
				t_start = mctp_ext_millis();
				break;

			case MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE:

				if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
					MCTP_SYS_ERR(
						"%s: MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE Failed EID: %d\n",
						__func__, eid_start);
				} else {
					/* Process the MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE */
					mctp_ret = mctp_requester_get_routing_table_get_response(
						ctrl, eid, MCTP_BINDING_PCIE, mctp_resp_msg, resp_msg_len,
						cmd->pcie.remove_duplicates,
						g_pci_own_eid, &entry_hdl);

					/* Free Rx packet */
					free(mctp_resp_msg);
					mctp_resp_msg = NULL;
					free(mctp_hdr_msg);
					mctp_hdr_msg = NULL;
				}				

				/* Retry if the device is not ready */
				if (mctp_ret == MCTP_RET_DEVICE_NOT_READY || mctp_ret == MCTP_RET_REQUEST_FAILED) {
					/* Make sure it's not timedout before continuing */
					if (timeout < MCTP_DEVICE_READY_DELAY) {
						/* Increment the timeout */
						timeout += MCTP_DEVICE_READY_DELAY;

						/* Set the discover mode as MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST */
						discovery_mode =
							MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;

						/* Sleep for a while */
						sleep(MCTP_DEVICE_READY_DELAY);
						break;
					}

					MCTP_SYS_ERR(
						"%s: Timedout[%d secs]  MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE\n",
						__func__, timeout);

					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"No valid routing table", EVT_CRITICAL,
						"Reset the baseboard");

					return MCTP_RET_DISCOVERY_FAILED;
				}

				/* Reset the timeout */
				timeout = 0;

				/* Check if next routing entry found and set discovery mode accordingly */
				if (MCTP_RET_ROUTING_TABLE_FOUND == mctp_ret) {
					MCTP_SYS_DEBUG("%s: Next entry found..\n",
							__func__);
					discovery_mode =
						MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;
					break;
				}
				
				while(routing_entry != NULL)
				{
					routing_entry = routing_entry->next;

					if(routing_entry == NULL)
						break;

					if (routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE &&
						(GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) == MCTP_ROUTING_ENTRY_BRIDGE ||
							GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) == MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS)) {
							eid_start = routing_entry->routing_table.starting_eid;
							g_remote_id = routing_entry->routing_table.phys_address[0] << 8|routing_entry->routing_table.phys_address[1];
							discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;
							break;
					}
				}
				entry_hdl = MCTP_ROUTING_ENTRY_START;

				if(discovery_mode == MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST)
					break;

				/* Get the start of Routing entry */
				routing_entry = g_routing_table_entries;
				while(routing_entry != NULL)
				{
					if ((routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
				     			routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM) &&
							GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) != MCTP_ROUTING_ENTRY_ENDPOINTS &&
					 		!routing_entry->probed)
						break;
					routing_entry = routing_entry->next;
				}

				/* Next step is to Get Endpoint UUID request */
				discovery_mode = MCTP_GET_EP_UUID_REQUEST;
				break;

			case MCTP_GET_EP_UUID_REQUEST:

				/* Send the MCTP_GET_EP_UUID_REQUEST */
				if (routing_entry) {
					/* Set the Start of EID */
					eid_start = routing_entry->routing_table
							.starting_eid;
					g_remote_id = match_bridge_routing_entry(routing_entry, g_target_bdf);

					MCTP_SYS_DEBUG(
						"%s: Send UUID Request for EID: 0x%x\n",
						__func__, eid_start);
					
					MCTP_SYS_DEBUG(
					"%s: Send VDM Support Request for remote id: %04x\n",
					__func__, g_remote_id);

					mctp_ret = mctp_requester_get_endpoint_uuid_send_request(
						ctrl->sock, bind_id, eid_start, g_pci_own_eid, g_remote_id);
					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						MCTP_SYS_ERR(
							"%s: Failed MCTP_GET_EP_UUID_REQUEST\n",
							__func__);
						doLog(ctrl->bus,
							"PCIe Device Enumeration Service",
							"Failed to get unique identifier for endpoint",
							EVT_CRITICAL,
							"Reset the baseboard");
						return MCTP_RET_DISCOVERY_FAILED;
					}

					/* Wait for the endpoint response */
					discovery_mode = MCTP_GET_EP_UUID_RESPONSE;
					/* Start time */
					t_start = mctp_ext_millis();
				} else {
					discovery_mode = MCTP_FINISH_DISCOVERY;
				}
				break;

			case MCTP_GET_EP_UUID_RESPONSE:

				if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
					MCTP_SYS_ERR(
						"%s: MCTP_GET_EP_UUID_RESPONSE Failed EID: %d\n",
						__func__, eid_start);
				} else {
					/* Process the MCTP_GET_EP_UUID_RESPONSE */
					mctp_ret = mctp_get_endpoint_uuid_response(
						eid_start, mctp_resp_msg, resp_msg_len);

					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						MCTP_SYS_ERR(
							"%s: MCTP_GET_EP_UUID_RESPONSE Failed\n",
							__func__);
					}
					/* Free Rx packet */
					free(mctp_resp_msg);
					mctp_resp_msg = NULL;
					free(mctp_hdr_msg);
					mctp_hdr_msg = NULL;
				}

				/* Increment the routing entry */
				while(routing_entry != NULL)
				{
					routing_entry = routing_entry->next;
					if (routing_entry != NULL && (routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
				     		routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM ) &&
							GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) != MCTP_ROUTING_ENTRY_ENDPOINTS &&
					 		!routing_entry->probed)
						break;
				}

				/* Continue probing all UUID requests */
				if (routing_entry) {
					/* Next step is to Get Endpoint UUID request */
					discovery_mode = MCTP_GET_EP_UUID_REQUEST;
					break;
				}

				/* Get the start of Routing entry */
				routing_entry = g_routing_table_entries;
				while(routing_entry != NULL)
				{
					if ((routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
				     		routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM ) &&
							GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) != MCTP_ROUTING_ENTRY_ENDPOINTS &&
					 		!routing_entry->probed)
						break;
					routing_entry = routing_entry->next;
				}
				discovery_mode = MCTP_GET_EP_VDM_SUPPORT_REQUEST;
				break;

			case MCTP_GET_EP_VDM_SUPPORT_REQUEST:

			/* Send the MCTP_GET_EP_VDM_Support_REQUEST */
			if (routing_entry) {
				/* Set the Start of EID */
				eid_start = routing_entry->routing_table
						.starting_eid;
				g_remote_id = match_bridge_routing_entry(routing_entry, g_target_bdf);

				MCTP_SYS_DEBUG(
					"%s: Send VDM Support Request for EID: 0x%x\n",
					__func__, eid_start);

				MCTP_SYS_DEBUG(
					"%s: Send VDM Support Request for remote id: %04x\n",
					__func__, g_remote_id);

				mctp_ret = mctp_requester_get_vdm_support_send_request(
					ctrl->sock, bind_id, eid_start, g_pci_own_eid, g_remote_id, v_id_set_selector);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_SYS_ERR(
						"%s: Failed MCTP_GET_EP_VDM Support_REQUEST\n",
						__func__);
					doLog(ctrl->bus,
					      "PCIe Device Enumeration Service",
					      "Failed to get unique identifier for endpoint",
					      EVT_CRITICAL,
					      "Reset the baseboard");
					return MCTP_RET_DISCOVERY_FAILED;
				}
			} else {
				discovery_mode = MCTP_FINISH_DISCOVERY;
			}

			/* Wait for the endpoint response */
			discovery_mode = MCTP_GET_EP_VDM_SUPPORT_RESPONSE;
			/* Start time */
			t_start = mctp_ext_millis();

			break;

		case MCTP_GET_EP_VDM_SUPPORT_RESPONSE:

			if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
				MCTP_SYS_ERR(
					"%s: MCTP_GET_EP_VDM_SUPPORT_RESPONSE Failed EID: %d\n",
					__func__, eid_start);
			} else {
				/* Process the MCTP_GET_EP_VDM_SUPPORT_RESPONSE */
				mctp_ret = mctp_requester_get_vdm_support_send_response(
					eid_start, mctp_resp_msg, resp_msg_len, &v_id_set_selector);

				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS && mctp_ret != MCTP_RET_SET_SELECTOR_FOUND) {
					MCTP_SYS_ERR(
						"%s: MCTP_GET_EP_VDM_SUPPORT_RESPONSE Failed\n",
						__func__);
				}
				/* Free Rx packet */
				free(mctp_resp_msg);
				mctp_resp_msg = NULL;
				free(mctp_hdr_msg);
				mctp_hdr_msg = NULL;
			}

			if (MCTP_RET_SET_SELECTOR_FOUND == mctp_ret) {
				MCTP_SYS_DEBUG("%s: Next entry found..\n",
						__func__);
				discovery_mode =
					MCTP_GET_EP_VDM_SUPPORT_REQUEST;
				break;
			}

			if(v_id_set_selector == 0xFF || mctp_ret != MCTP_RET_REQUEST_SUCCESS){
				/* Increment the routing entry */
				while(routing_entry != NULL)
				{
					routing_entry = routing_entry->next;

					if(routing_entry == NULL)
						break;

					if ((routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
					    	routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM) &&
					    GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) != MCTP_ROUTING_ENTRY_ENDPOINTS &&
					 	!routing_entry->probed)
					        break;
				}

				/* Continue probing all VDM requests */
				if (routing_entry) {
					/* Next step is to Get Endpoint VDM Suppoet request */
					v_id_set_selector = 0;
					discovery_mode = MCTP_GET_EP_VDM_SUPPORT_REQUEST;
					break;
				}
			}			

			/* Get the start of Routing entry */
			routing_entry = g_routing_table_entries;
			while(routing_entry != NULL)
			{
				if ((routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
				     routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM ) &&
				     GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) != MCTP_ROUTING_ENTRY_ENDPOINTS &&
					 !routing_entry->probed)
				        break;
				routing_entry = routing_entry->next;
			}
			discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;
			break;

			case MCTP_GET_MSG_TYPE_REQUEST:

				/* Send the MCTP_GET_EP_UUID_REQUEST */
				if (routing_entry) {
					/* Set the Start of EID */
					eid_start = routing_entry->routing_table
								.starting_eid;
					g_remote_id = match_bridge_routing_entry(routing_entry, g_target_bdf);

					MCTP_SYS_DEBUG(
						"%s: Send Get Msg type Request for EID: 0x%x\n",
						__func__, eid_start);

					MCTP_SYS_DEBUG(
					"%s: Send VDM Support Request for remote id: %04x\n",
					__func__, g_remote_id);

					mctp_ret = mctp_requester_get_msg_type_send_request(
						ctrl->sock, bind_id, eid_start, g_pci_own_eid, g_remote_id);
					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						MCTP_SYS_ERR(
							"%s: Failed MCTP_GET_MSG_TYPE_REQUEST\n",
							__func__);
						doLog(ctrl->bus,
							"PCIe Device Enumeration Service",
							"Failed to get supported message types for endpoint",
							EVT_CRITICAL,
							"Reset the baseboard");
						return MCTP_RET_DISCOVERY_FAILED;
					}
					/* Wait for the endpoint response */
					discovery_mode = MCTP_GET_MSG_TYPE_RESPONSE;
					/* Start time */
					t_start = mctp_ext_millis();
				} else {
					discovery_mode = MCTP_FINISH_DISCOVERY;
				}

				break;

			case MCTP_GET_MSG_TYPE_RESPONSE:

				if (mctp_ret == MCTP_RET_REQUEST_FAILED) {
					MCTP_SYS_ERR(
						"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed EID: %d\n",
						__func__, eid_start);
				} else {
					/* Process the MCTP_GET_MSG_TYPE_RESPONSE */
					mctp_ret = mctp_get_msg_type_response(
						eid_start, mctp_resp_msg, resp_msg_len);

					/* Free Rx packet */
					free(mctp_resp_msg);
					mctp_resp_msg = NULL;
					free(mctp_hdr_msg);
					mctp_hdr_msg = NULL;

					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						MCTP_SYS_ERR(
							"%s: MCTP_GET_MSG_TYPE_RESPONSE Failed\n",
							__func__);
					}
				}

				/* Increment the routing entry */
				while(routing_entry != NULL)
				{
					routing_entry = routing_entry->next;
					if (routing_entry != NULL && 
							(routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
				     		routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM ) &&
							GET_ROUTING_ENTRY_TYPE(routing_entry->routing_table.entry_type) != MCTP_ROUTING_ENTRY_ENDPOINTS &&
							!routing_entry->probed)
						break;
				}

				/* Continue probing all Msg type requests */
				if (routing_entry) {
					/* Next step is to Get Endpoint UUID request */
					discovery_mode = MCTP_GET_MSG_TYPE_REQUEST;
					break;
				}

				/* Finally update the global mctp_discovered_endpoints */
				MCTP_SYS_DEBUG("%s: Completed discovery process..\n",
						__func__);
				discovery_mode = MCTP_FINISH_DISCOVERY;
				daemon_mode = true;
				break;

			default:
				break;
		}

	} while (discovery_mode != MCTP_FINISH_DISCOVERY);

	if (ctrl->update_routing_table) {
		/* Display all Routing table details */
		MCTP_SYS_DEBUG("%s: Obtained Routing table entries\n", __func__);
		mctp_routing_entry_display();

		/* Display all UUID details */
		MCTP_SYS_DEBUG("%s: Obtained UUID entries\n", __func__);
		mctp_uuid_display();

		MCTP_SYS_DEBUG("%s: Obtained VDM entries\n", __func__);
		mctp_vdm_display();

		/* Display all message type details */
		MCTP_SYS_DEBUG("%s: Obtained Message type entries\n", __func__);
		mctp_msg_types_display();
	}
	
	return MCTP_RET_DISCOVERY_SUCCESS;
}

/* MCTP discovery request receive routine */
mctp_ret_codes_t mctp_busowner_mode_ctrl_cmd_responder(mctp_ctrl_t *ctrl,
					       mctp_binding_ids_t bind_id,
						   mctp_eid_t eid,
					       uint8_t **mctp_msg,
					       size_t *mctp_len __unused,
						   uint8_t ** mctp_hdr __unused)
{
	(void)eid;
	(void)ctrl;
	(void)bind_id;
	mctp_ret_codes_t mctp_ret;
	mctp_eid_t own_eid = g_pci_own_eid;
    struct mctp_ctrl_cmd_msg_hdr* msg_hdr = (struct mctp_ctrl_cmd_msg_hdr * )*mctp_msg;
	struct get_routing_table_entry routing_table_entry;
	mctp_eid_t eid_pool_start;
	size_t eid_pool_size;
	mctp_ctrl_cmd_set_eid_op set_eid_op;
	mctp_ctrl_cmd_alloc_eid_op alloc_eid_op;
	int ret;

	MCTP_SYS_DEBUG("%s: mctp_busowner_mode_ctrl_cmd_responder \n", __func__);
	if (!(msg_hdr->rq_dgram_inst & MCTP_CTRL_HDR_FLAG_REQUEST))
	{
		switch (msg_hdr->command_code)
		{
			case MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY:
				g_endpoint_dicovered = 1;
				break;

			case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY:

				/* Update the EID operation and EID number */
				set_eid_op = set_eid;

				/* Send the MCTP_SET_EP_REQUEST */
				mctp_ret = mctp_requester_set_eid_send_request(ctrl->sock, bind_id, set_eid_op, g_pci_bridge_pool_start ++,
																own_eid, g_target_bdf);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_SYS_ERR(
						"%s: Failed MCTP_SET_EP_REQUEST\n",
						__func__);
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");
					return MCTP_RET_REQUEST_FAILED;
				}

				break;

			case MCTP_CTRL_CMD_SET_ENDPOINT_ID:

				/* Process the MCTP_SET_EP_RESPONSE */
				mctp_ret = mctp_requester_set_eid_get_response(*mctp_msg,
							     *mctp_len,
							     &eid,
							     &eid_pool_size);

				memset(&routing_table_entry , 0, sizeof(struct get_routing_table_entry));
				eid_pool_size > 0 ?
					SET_ROUTING_ENTRY_TYPE(routing_table_entry.entry_type, MCTP_ROUTING_ENTRY_BRIDGE) : SET_ROUTING_ENTRY_TYPE(routing_table_entry.entry_type, MCTP_ROUTING_ENTRY_ENDPOINTS);
				routing_table_entry.starting_eid = eid;
				routing_table_entry.phys_transport_binding_id = MCTP_BINDING_PCIE;
				routing_table_entry.eid_range_size = 1;
				routing_table_entry.phys_address_size = 2;
				routing_table_entry.phys_address[0] = g_remote_id >> 8;
				routing_table_entry.phys_address[1] = g_remote_id;

				/* Add the entry to a linked list */
				ret = mctp_routing_entry_add(
					&routing_table_entry);
				if (ret < 0) {
					MCTP_SYS_ERR(
						"%s: Failed to update global routing table..\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}

				if (eid_pool_size > 0) {
					/* Update the Allocate EIDs operation, number of EIDs, Starting EID */
					alloc_eid_op = alloc_req_eid;

					/* Set the start of EID */
					eid_pool_start = g_pci_bridge_pool_start;
					g_pci_bridge_pool_start += eid_pool_size;

					/* Send the MCTP_ALLOCATE_EP_ID_REQUEST */
					mctp_ret = mctp_requester_alloc_eid_send_request(
						ctrl->sock, bind_id, eid,
						(mctp_ctrl_cmd_set_eid_op)alloc_eid_op,
						eid_pool_size, eid_pool_start, g_remote_id, own_eid);
					if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
						MCTP_SYS_ERR(
							"%s: Failed MCTP_SET_EP_REQUEST\n",
							__func__);
						doLog(ctrl->bus,
							"PCIe Device Enumeration Service",
							"Failed to discover", EVT_CRITICAL,
							"Reset the baseboard");
						return MCTP_RET_DISCOVERY_FAILED;
					}
				} 

				break;

			case MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS:

				/* Process the MCTP_ALLOCATE_EP_ID_RESPONSE */
				mctp_ret = mctp_requester_alloc_eid_get_response(*mctp_msg,
									*mctp_len, &eid_pool_start, &eid_pool_size);

				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_SYS_ERR(
						"%s: Failed MCTP_ALLOCATE_EP_ID_RESPONSE\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}

				memset(&routing_table_entry , 0, sizeof(struct get_routing_table_entry));
				SET_ROUTING_ENTRY_TYPE(routing_table_entry.entry_type, MCTP_ROUTING_ENTRY_ENDPOINTS);
				routing_table_entry.starting_eid = eid_pool_start;
				routing_table_entry.phys_transport_binding_id = MCTP_BINDING_PCIE;
				routing_table_entry.eid_range_size = eid_pool_size;
				routing_table_entry.phys_address_size = 2;
				routing_table_entry.phys_address[0] = g_remote_id >> 8;
				routing_table_entry.phys_address[1] = g_remote_id;

				/* Add the entry to a linked list */
				ret = mctp_routing_entry_add(
					&routing_table_entry);
				if (ret < 0) {
					MCTP_SYS_ERR(
						"%s: Failed to update global routing table..\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}
				break;

			case MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES:
			case MCTP_CTRL_CMD_GET_ENDPOINT_UUID:
			case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT:
			case MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT:
				return MCTP_CMD_FAILED;

			default:
				break;
		};
		
		return MCTP_CMD_SUCCESS;
	} else {
		// handle incoming request
		return MCTP_CMD_SUCCESS;
	}

	return MCTP_CMD_FAILED;

}
