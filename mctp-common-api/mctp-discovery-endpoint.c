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
#include "mctp-requester.h"
#include "mctp-responder.h"
#include "time.h"
#include "mctp-utils.h"
#include "mctp-ext-sdbus.h"
#ifdef MCTP_IN_KERNEL
#include "mctp-netlink.h"
#include "mctp-ext-socket.h"
#include "mctp-socket.h"
#include "mctp-discovery-kernel.h"
#endif

extern uint8_t g_eid_pool_size;
extern uint8_t g_eid_pool_start;
extern mctp_routing_table_t *g_routing_table_entries;
extern const uint8_t MCTP_ROUTING_ENTRY_START;
static int mctp_endpoint_sock = 0;

/* PCIe target bdf */
static int g_target_bdf = 0;
/* The EIDs and pool start information would be obtaind from commandline */
static uint8_t g_pci_bridge_eid, g_pci_own_eid, g_pci_bridge_pool_start;
static uint8_t g_endpoint_dicovered = 0;
static uint16_t g_remote_id;
#define MAX_DISCOVERY_COMMAND_TIME_OUT  999
#define MAX_DISCOVERY_RETRY_PERIOD 60

/* MCTP discovery response receive routine */
static mctp_ret_codes_t mctp_discover_request(mctp_ctrl_t *ctrl,
					       mctp_discovery_mode mode,
					       mctp_eid_t *eid,
					       uint8_t **mctp_resp_msg,
					       size_t *mctp_resp_len,
   						   uint8_t **mctp_hdr_msg)
{
#ifdef MCTP_IN_KERNEL
	int sock;
	if(g_endpoint_dicovered) {
		MCTP_SYS_TRACE("%s: Using ctrl->sock %d\n", __func__, ctrl->sock);
		(void) mctp_endpoint_sock;
		sock = ctrl->sock;
	} else {
		MCTP_SYS_TRACE("%s: Using mctp_endpoint_sock %d\n", __func__, mctp_endpoint_sock);
		sock = mctp_endpoint_sock;//ctrl->sock;
		(void)ctrl;
	}
#else
	(void) mctp_endpoint_sock;
	int sock = ctrl->sock;
#endif

	mctp_requester_rc_t mctp_ret;
	//char *device_name = "PCIe Device Enumeration Service";
    
	/* Ignore request commands */
	switch (mode) {
	case MCTP_PREPARE_FOR_EP_DISCOVERY_REQUEST:
	case MCTP_EP_DISCOVERY_REQUEST:
	case MCTP_DISCOVERY_NOTIFY_REQUEST:
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
	case MCTP_WAITING_BUSOWNER_CMD:
	
#ifdef MCTP_IN_KERNEL
		*eid = 0xff;
#endif

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
mctp_ret_codes_t mctp_endpoint_mode_discover_endpoints(const mctp_cmdline_args_t *cmd,
					 mctp_ctrl_t *ctrl)
{
	static int discovery_mode = MCTP_SET_EP_RESPONSE;
	bool daemon_mode = g_endpoint_dicovered;

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
	//g_target_bdf = mctp_ctrl_get_target_bdf(cmd);
	int64_t t_start, t_end;
	bool get_busowner_routing_table = false;

	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 100* 1000000;  // 50 ms

	/* Update the EID lists */
#ifdef MCTP_IN_KERNEL
	if (!mctp_endpoint_sock) mctp_endpoint_socket_init(&mctp_endpoint_sock, NULL, 0, 5000);
	uint8_t active_binding = ctrl->active_binding;
	g_pci_own_eid = cmd->kernel.binding[active_binding].own_eid;
	g_pci_bridge_eid = cmd->kernel.binding[active_binding].eid;
	g_pci_bridge_pool_start = cmd->kernel.binding[active_binding].eid_pool_start;

	if (mctp_nl_add_route(g_pci_bridge_eid) < 0) {
		MCTP_SYS_ERR("%s: Failed to add route for eid %d\n", __func__,
			      g_pci_bridge_eid);
	}

	mctp_update_endpoint_hwinfo(cmd->kernel.binding[active_binding].dest_slave_addr, cmd->kernel.binding[active_binding].slave_addr_len);
	if (mctp_nl_add_neigh(g_pci_bridge_eid) < 0) {
		MCTP_SYS_ERR("%s: Failed to add neigh for eid %d\n", __func__,
			      g_pci_bridge_eid);
	}
	// if (!g_endpoint_dicovered) discovery_mode = MCTP_DISCOVERY_NOTIFY_REQUEST;
#endif

	t_start = mctp_ext_millis();

	if(daemon_mode){
		discovery_mode = ctrl-> update_routing_table ? MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST: MCTP_WAITING_BUSOWNER_CMD;
		MCTP_SYS_DEBUG("%sStart endpoint mode partial discover \n", __func__);
	}

	MCTP_SYS_DEBUG(
		"%s: pci_own_eid: %d, pci_bridge_eid: %d, pci_bridge_pool_start: %d\n",
		__func__, g_pci_own_eid, g_pci_bridge_eid,
		g_pci_bridge_pool_start);

	do {
		/* Wait for MCTP response */
		mctp_ret =
			mctp_discover_request(ctrl, discovery_mode, &eid,
					       &mctp_resp_msg, &resp_msg_len, &mctp_hdr_msg);

		MCTP_SYS_DEBUG("mctp_discover_request = %d, dicovered = %d \n", mctp_ret, g_endpoint_dicovered);

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
			if ((discovery_mode != MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE) &&
				(discovery_mode != MCTP_GET_EP_UUID_RESPONSE) &&
			    (discovery_mode != MCTP_GET_EP_VDM_SUPPORT_RESPONSE) &&
			    (discovery_mode != MCTP_GET_MSG_TYPE_RESPONSE)) {
				MCTP_SYS_DEBUG(
					"%s: Unexpected failure %d, mode[%d]\n",
					__func__, mctp_ret, discovery_mode);					

				if (!g_endpoint_dicovered) {
					t_end = mctp_ext_millis();
					if ((t_end - t_start) / 1000 > MAX_DISCOVERY_RETRY_PERIOD) {
						return MCTP_RET_DISCOVERY_FAILED;
					}
					continue;
				} else if (discovery_mode == MCTP_WAITING_BUSOWNER_CMD) {
					discovery_mode = MCTP_FINISH_DISCOVERY;
				}
			}
		} else if(discovery_mode != MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST &&
					discovery_mode !=  MCTP_GET_EP_UUID_REQUEST &&
					discovery_mode !=  MCTP_GET_EP_VDM_SUPPORT_REQUEST &&
					discovery_mode !=  MCTP_GET_MSG_TYPE_REQUEST &&
					discovery_mode !=  MCTP_DISCOVERY_NOTIFY_REQUEST) {
			//g_target_bdf = mctp_ctrl_get_target_bdf(cmd);
			mctp_ret_codes_t mctp_responder_ret = mctp_endpoint_mode_ctrl_cmd_responder(ctrl, bind_id, eid, &mctp_resp_msg, &resp_msg_len, &mctp_hdr_msg);
			
			switch(mctp_responder_ret)
			{
				case MCTP_RET_DISCOVERY_SUCCESS:
					discovery_mode = MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST;
					/* Free Rx packet */
					free(mctp_resp_msg);
					mctp_resp_msg = NULL;
					free(mctp_hdr_msg);
					mctp_hdr_msg = NULL;
					continue;			

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
							"%s: MCTP Rx Command Timed out (waited %f seconds) \n discovery_mode = %d\n",
							__func__,
							(float)(t_end - t_start) / 1000, discovery_mode);

						if (discovery_mode == MCTP_GET_ROUTING_TABLE_ENTRIES_RESPONSE) {
							MCTP_SYS_DEBUG(
							"%s: Send Get Routing Table Request timeout\n",
							__func__);
							mctp_ret = MCTP_RET_REQUEST_FAILED;
							break;
						} else if (discovery_mode == MCTP_GET_EP_UUID_RESPONSE) {
							MCTP_SYS_DEBUG(
							"%s: Send UUID Request timeout\n",
							__func__);
							mctp_ret = MCTP_RET_REQUEST_FAILED;
							break;
						} else if (discovery_mode == MCTP_GET_EP_VDM_SUPPORT_RESPONSE) {
							MCTP_SYS_DEBUG(
							"%s: Send Get VDM support Request timeout\n",
							__func__);
							mctp_ret = MCTP_RET_REQUEST_FAILED;
							break;
						} else if (discovery_mode == MCTP_GET_MSG_TYPE_RESPONSE) {
							MCTP_SYS_DEBUG(
							"%s: Send Get Msg type Request timeout\n",
							__func__);
							mctp_ret = MCTP_RET_REQUEST_FAILED;
							break;
						} else if (discovery_mode == MCTP_WAITING_BUSOWNER_CMD) {
							discovery_mode = MCTP_FINISH_DISCOVERY;
							MCTP_SYS_DEBUG("%s Partial discover finish\n", __func__);
							break;
						} else {
							mctp_ret = MCTP_RET_REQUEST_FAILED;
						}
					} else {
						continue;
					}

				case MCTP_CMD_FAILED:
				default:
					break;
			}
		}
		
		switch(discovery_mode) {
		case MCTP_DISCOVERY_NOTIFY_REQUEST:
			/* Send the MCTP_DISCOVERY_NOTIFY_REQUEST */
			mctp_ret = mctp_requester_discovery_notify_send_request(
				ctrl->sock, bind_id, g_pci_own_eid, g_remote_id);
			if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
				MCTP_SYS_ERR(
					"%s: Failed MCTP_DISCOVERY_NOTIFY_REQUEST\n",
					__func__);
				//return MCTP_RET_DISCOVERY_FAILED;
			}

			/* Wait for the endpoint response */
			discovery_mode =
				MCTP_SET_EP_RESPONSE;

			/* Start time */
			t_start = mctp_ext_millis();
			break;

		case MCTP_GET_ROUTING_TABLE_ENTRIES_REQUEST:

			if (!get_busowner_routing_table) {
				eid_start = g_pci_bridge_eid;
				g_remote_id = g_target_bdf;
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
			if (mctp_ret == MCTP_RET_REQUEST_FAILED || mctp_ret == MCTP_RET_DEVICE_NOT_READY) {
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

				if (!get_busowner_routing_table)
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
				nanosleep(&ts, NULL);
				break;
			}

			if (entry_hdl == 0xFF) {
				if (!get_busowner_routing_table) {
					get_busowner_routing_table = true;
					routing_entry = g_routing_table_entries;
				}
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
				     routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM ) &&
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
					"%s: Send UUID Request for remote id: %04x\n",
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
						/* Update UUID private params to export to upper layer */
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

				if(routing_entry == NULL)
					break;

				if ((routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
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

				/* Wait for the endpoint response */
				discovery_mode = MCTP_GET_EP_VDM_SUPPORT_RESPONSE;
				/* Start time */
				t_start = mctp_ext_millis();
			} else {
				discovery_mode = MCTP_FINISH_DISCOVERY;
			}
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
					     routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_VDM ) &&
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
				routing_entry->probed = true;

				MCTP_SYS_DEBUG(
					"%s: Send Get Msg type Request for EID: 0x%x (%d)\n",
					__func__, eid_start, routing_entry->probed);

				MCTP_SYS_DEBUG(
					"%s: Send Get Msg type Request for remote id: %04x\n",
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
#ifdef MCTP_IN_KERNEL				
				/* Process the MCTP_GET_MSG_TYPE_RESPONSE */
				mctp_ret = mctp_kernel_get_msg_type_response(
					eid_start, mctp_resp_msg, resp_msg_len, cmd->kernel.binding[active_binding].binding);
#else
				/* Process the MCTP_GET_MSG_TYPE_RESPONSE */
				mctp_ret = mctp_get_msg_type_response(
					eid_start, mctp_resp_msg, resp_msg_len);
#endif

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

				if(routing_entry == NULL)
					break;

				if ((routing_entry->routing_table.phys_transport_binding_id == MCTP_BINDING_PCIE ||
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
			
			if(daemon_mode){
				discovery_mode = MCTP_WAITING_BUSOWNER_CMD;
				t_start = mctp_ext_millis();
			}else{
				discovery_mode = MCTP_FINISH_DISCOVERY;
			}

			break;

		case MCTP_WAITING_BUSOWNER_CMD:
			MCTP_SYS_DEBUG("%s: Waiting buswoner command...\n",
						__func__);
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
mctp_ret_codes_t mctp_endpoint_mode_ctrl_cmd_responder(mctp_ctrl_t *ctrl,
					       mctp_binding_ids_t bind_id,
						   mctp_eid_t eid,
					       uint8_t **mctp_msg,
					       size_t *mctp_len __unused,
						   uint8_t ** mctp_hdr)
{
	mctp_ret_codes_t mctp_ret;
	mctp_eid_t own_eid = g_pci_own_eid;
    struct mctp_ctrl_cmd_msg_hdr* msg_hdr = (struct mctp_ctrl_cmd_msg_hdr * )*mctp_msg;
	MCTP_SYS_DEBUG("%s: mctp_endpoint_mode_ctrl_cmd_responder \n", __func__);
	if (msg_hdr->rq_dgram_inst & MCTP_CTRL_HDR_FLAG_REQUEST)
	{
		switch (msg_hdr->command_code)
		{
			case MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY:

				/* Send the prepare endpoint discovery message */
				mctp_ret = mctp_prepare_responder_discovery_send_response(
					ctrl->sock, bind_id, eid, *mctp_hdr, g_remote_id, (struct mctp_ctrl_cmd_prepare_ep_discovery *)*mctp_msg);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");
					MCTP_SYS_ERR(
						"%s: Failed MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}
				g_endpoint_dicovered = 0;
				break;

			case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY:

				if (g_endpoint_dicovered)
					break;

				/* Send the prepare endpoint message */
				mctp_ret = mctp_responder_discovery_send_response(ctrl->sock,
									bind_id, eid, *mctp_hdr, g_remote_id, (struct mctp_ctrl_cmd_ep_discovery *)*mctp_msg);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");

					MCTP_SYS_ERR(
						"%s: Failed MCTP_EP_DISCOVERY_RESPONSE\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}

				break;

			case MCTP_CTRL_CMD_SET_ENDPOINT_ID:

				g_pci_own_eid = ((struct mctp_ctrl_cmd_set_eid *)*mctp_msg )->eid;
				g_pci_bridge_eid = eid;
				g_target_bdf = g_remote_id;
				ctrl->local_eid = g_pci_own_eid;
				/* Send the set endpoint id message */
				mctp_ret = mctp_responder_set_eid_send_response(
					ctrl->sock, bind_id, eid, *mctp_hdr, g_remote_id, (struct mctp_ctrl_cmd_set_eid *)*mctp_msg);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					MCTP_SYS_ERR(
						"%s: Failed MCTP_SET_EP_RESPONSE\n",
						__func__);
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");
					return MCTP_RET_REQUEST_FAILED;
				}

				if (!g_endpoint_dicovered || own_eid != g_pci_own_eid) {
					g_endpoint_dicovered = 1;
					return MCTP_RET_DISCOVERY_SUCCESS;
				}

				break;

			case MCTP_CTRL_CMD_GET_ENDPOINT_ID:

				/* Send the get endpoint id message */
				mctp_ret = mctp_responder_get_eid_send_response(ctrl->sock,
									bind_id, eid, *mctp_hdr, g_remote_id, g_pci_own_eid, (struct mctp_ctrl_cmd_get_eid *)*mctp_msg);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");

					MCTP_SYS_ERR(
						"%s: Failed MCTP_EP_ID_RESPONSE\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}

				break;

			case MCTP_CTRL_CMD_GET_ENDPOINT_UUID:

				/* Send the get endpoint uuid message */
				mctp_ret = mctp_responder_get_uuid_send_response(ctrl->sock,
									bind_id, eid, *mctp_hdr, g_remote_id, (struct mctp_ctrl_cmd_get_uuid *)*mctp_msg);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");

					MCTP_SYS_ERR(
						"%s: Failed MCTP_EP_UUID_RESPONSE\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}

				break;

			case MCTP_CTRL_CMD_GET_VERSION_SUPPORT:

				/* Send the get version support message */
				mctp_ret = mctp_responder_get_mctp_ver_support_send_response(ctrl->sock,
									bind_id, eid, *mctp_hdr, g_remote_id, (struct mctp_ctrl_cmd_get_mctp_ver_support *)*mctp_msg);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");

					MCTP_SYS_ERR(
						"%s: Failed MCTP_EP_VER_SUPPORT_RESPONSE\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}

				break;

			case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT:

				/* Send the get vendor_message support message */
				mctp_ret = mctp_responder_get_msg_type_support_send_response(ctrl->sock,
									bind_id, eid, *mctp_hdr, g_remote_id, (struct mctp_ctrl_cmd_get_msg_type_support *)*mctp_msg);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");

					MCTP_SYS_ERR(
						"%s: Failed MCTP_EP_MSG_TYPE_SUPPORT_RESPONSE\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}

				break;

			case MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT:

				/* Send the get vendor_message support message */
				mctp_ret = mctp_responder_get_vdm_support_send_response(ctrl->sock,
									bind_id, eid, *mctp_hdr, g_remote_id, (struct mctp_ctrl_cmd_get_vdm_support *)*mctp_msg);
				if (mctp_ret != MCTP_RET_REQUEST_SUCCESS) {
					doLog(ctrl->bus,
						"PCIe Device Enumeration Service",
						"Failed to discover", EVT_CRITICAL,
						"Reset the baseboard");

					MCTP_SYS_ERR(
						"%s: Failed MCTP_EP_MSG_TYPE_SUPPORT_RESPONSE\n",
						__func__);
					return MCTP_RET_REQUEST_FAILED;
				}

				break;

			default:
				return MCTP_RET_REQUEST_FAILED;
		};
		return MCTP_CMD_SUCCESS;
	}

	return MCTP_CMD_FAILED;

}
