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


static const guid_t g_endpoint_uuid = {.raw = {0xa3, 0x97, 0xa2, 0x55, 0x53, 0xbe, 0x41, 0xfc, 0x99, 0x6b, 0x52, 0x14, 0x13, 0xe9, 0xe2, 0x2d}};

/* Send function for Prepare for Endpoint discovery */
mctp_ret_codes_t 
mctp_prepare_responder_discovery_send_response(int sock_fd, mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, 
                        uint16_t remote_id, struct mctp_ctrl_cmd_prepare_ep_discovery* prep_ep_discovery_req)
{
	//bool req_ret;
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_resp_prepare_discovery prep_ep_discovery;
	struct mctp_ctrl_resp ep_discovery_resp;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;

	/* Set private binding */
	if (MCTP_BINDING_PCIE== bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_BY_ID;
		pvt_binding_pcie.remote_id = remote_id;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	} else if (MCTP_BINDING_SPI == bind_id) {
		memset(&pvt_binding_spi, 0, sizeof(pvt_binding_spi));
		pvt_binding = &pvt_binding_spi;
		binding_size = sizeof(pvt_binding_spi);
	}

	/* Prepare the endpoint discovery message */
    memcpy(&prep_ep_discovery, prep_ep_discovery_req, sizeof(struct mctp_ctrl_cmd_prepare_ep_discovery));
    prep_ep_discovery.ctrl_hdr.rq_dgram_inst &= ~ MCTP_CTRL_HDR_FLAG_REQUEST;
    prep_ep_discovery.completion_code = MCTP_CTRL_CC_SUCCESS;

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_prepare_discovery) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	MCTP_SYS_DEBUG("%s: message length: %zu\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_discovery_resp, 0, sizeof(ep_discovery_resp));

	/* Copy to Tx packet */
	memcpy(&ep_discovery_resp, &prep_ep_discovery,
	       sizeof(struct mctp_ctrl_resp_prepare_discovery));

	mctp_print_resp_msg(&ep_discovery_resp,
			   "MCTP_PREPARE_FOR_EP_DISCOVERY_RESPONSE", msg_len);

	/* Send the request message over socket */
	MCTP_SYS_DEBUG("%s: Sending EP response\n", __func__);
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_discovery_resp,
		sizeof(struct mctp_ctrl_resp_prepare_discovery), hdr, &bind_id,
		pvt_binding, binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Endpoint discovery */
mctp_ret_codes_t mctp_responder_discovery_send_response(int sock_fd,
						mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, 
                        uint16_t remote_id, struct mctp_ctrl_cmd_ep_discovery* ep_discovery_req)
{
	mctp_requester_rc_t mctp_ret;
	struct mctp_ctrl_resp_endpoint_discovery ep_discovery;
	struct mctp_ctrl_resp ep_resp;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;

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

	/* Prepare the endpoint discovery message */
    memcpy(&ep_discovery, ep_discovery_req, sizeof(struct mctp_ctrl_cmd_ep_discovery));
    ep_discovery.ctrl_hdr.rq_dgram_inst &= ~ MCTP_CTRL_HDR_FLAG_REQUEST;
    ep_discovery.completion_code = MCTP_CTRL_CC_SUCCESS;

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_endpoint_discovery) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	MCTP_SYS_DEBUG("%s: message length: %zu\n", __func__, msg_len);

	/* Initialize the buffers */
	memset(&ep_resp, 0, sizeof(ep_resp));

	/* Copy to Tx packet */
	memcpy(&ep_resp, &ep_discovery,
	       sizeof(struct mctp_ctrl_resp_endpoint_discovery));

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_resp,
		sizeof(struct mctp_ctrl_resp_endpoint_discovery), hdr, &bind_id,
		pvt_binding, binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Set Endpoint ID */
mctp_ret_codes_t mctp_responder_set_eid_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, 
                       uint16_t remote_id, struct mctp_ctrl_cmd_set_eid *set_eid_req)
{
	mctp_requester_rc_t mctp_ret;

	struct mctp_ctrl_resp_set_eid set_eid_resp;
	struct mctp_ctrl_resp ep_resp;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;

	/* Set private binding */
	if (MCTP_BINDING_PCIE== bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_BY_ID;
		pvt_binding_pcie.remote_id = remote_id;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	} else if (MCTP_BINDING_SPI == bind_id) {
		memset(&pvt_binding_spi, 0, sizeof(pvt_binding_spi));
		pvt_binding = &pvt_binding_spi;
		binding_size = sizeof(pvt_binding_spi);
	}

	/* Encode Set Endpoint ID message */
    memcpy(&set_eid_resp, set_eid_req, sizeof(struct mctp_ctrl_cmd_set_eid));
    set_eid_resp.ctrl_hdr.rq_dgram_inst &= ~ MCTP_CTRL_HDR_FLAG_REQUEST;
    set_eid_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
    set_eid_resp.eid_pool_size = MCTP_SETEID_ALLOC_STATUS_EID_POOL_NOT_REQ;
    set_eid_resp.status = MCTP_SETEID_ASSIGN_STATUS_ACCEPTED;
    set_eid_resp.eid_set = set_eid_req->eid;

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_set_eid) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_resp, 0, sizeof(ep_resp));

	/* Copy to Tx packet */
	memcpy(&ep_resp, &set_eid_resp, sizeof(struct mctp_ctrl_resp_set_eid));

	mctp_print_resp_msg(&ep_resp, "MCTP_SET_EP_RESPONSE", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_resp,
		sizeof(struct mctp_ctrl_resp_set_eid), hdr, &bind_id, pvt_binding,
		binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get Endpoint ID */
mctp_ret_codes_t mctp_responder_get_eid_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, 
                       uint16_t remote_id, mctp_eid_t pci_own_eid, struct mctp_ctrl_cmd_get_eid *get_eid_req)
{
	mctp_requester_rc_t mctp_ret;

	struct mctp_ctrl_resp_get_eid get_eid_resp = {0};
	struct mctp_ctrl_resp ep_resp;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;

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

	/* Encode Set Endpoint ID message */
    memcpy(&get_eid_resp, get_eid_req, sizeof(struct mctp_ctrl_cmd_get_eid));
    get_eid_resp.ctrl_hdr.rq_dgram_inst &= ~ MCTP_CTRL_HDR_FLAG_REQUEST;
    get_eid_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
	get_eid_resp.eid = pci_own_eid;
	SET_ENDPOINT_TYPE (get_eid_resp.eid_type, MCTP_SIMPLE_ENDPOINT);
	SET_ENDPOINT_ID_TYPE (get_eid_resp.eid_type, MCTP_DYNAMIC_EID);
	get_eid_resp.medium_data = 0x00;

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_get_eid) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_resp, 0, sizeof(ep_resp));

	/* Copy to Tx packet */
	memcpy(&ep_resp, &get_eid_resp, sizeof(struct mctp_ctrl_resp_get_eid));

	mctp_print_resp_msg(&ep_resp, "MCTP_GET_EP_RESPONSE", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_resp,
		sizeof(struct mctp_ctrl_resp_get_eid), hdr, &bind_id, pvt_binding,
		binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get Endpoint UUID */
mctp_ret_codes_t mctp_responder_get_uuid_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, 
                       uint16_t remote_id, struct mctp_ctrl_cmd_get_uuid *get_uuid_req)
{
	mctp_requester_rc_t mctp_ret;

	struct mctp_ctrl_resp_get_uuid get_uuid_resp;
	struct mctp_ctrl_resp ep_resp;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;

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

	/* Encode Get Endpoint UUID message */
    memcpy(&get_uuid_resp, get_uuid_req, sizeof(struct mctp_ctrl_cmd_get_uuid));
    get_uuid_resp.ctrl_hdr.rq_dgram_inst &= ~ MCTP_CTRL_HDR_FLAG_REQUEST;
    get_uuid_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
	memcpy(&get_uuid_resp.uuid, &g_endpoint_uuid, sizeof(g_endpoint_uuid));

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_get_uuid) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_resp, 0, sizeof(ep_resp));

	/* Copy to Tx packet */
	memcpy(&ep_resp, &get_uuid_resp, sizeof(struct mctp_ctrl_resp_get_uuid));

	mctp_print_resp_msg(&ep_resp, "MCTP_GET_UUID_RESPONSE", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_resp,
		sizeof(struct mctp_ctrl_resp_get_uuid), hdr, &bind_id, pvt_binding,
		binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get MCTP version support */
mctp_ret_codes_t mctp_responder_get_mctp_ver_support_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, 
                       uint16_t remote_id, struct mctp_ctrl_cmd_get_mctp_ver_support *get_mctp_ver_support_req)
{
	mctp_requester_rc_t mctp_ret;

	struct mctp_ctrl_resp_get_mctp_ver_support get_mctp_ver_support_resp;
	struct mctp_ctrl_resp ep_resp;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;

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

	/* Encode get MCTP version support message */
    memcpy(&get_mctp_ver_support_resp, get_mctp_ver_support_req, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support));
    get_mctp_ver_support_resp.ctrl_hdr.rq_dgram_inst &= ~ MCTP_CTRL_HDR_FLAG_REQUEST;
    get_mctp_ver_support_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
	get_mctp_ver_support_resp.number_of_entries = 4;

	struct version_entry versions [4] = {
		{ 0xF1, 0xF0, 0xFF, 0x00},
		{ 0xF1, 0xF1, 0xFF, 0x00}, 
		{ 0xF1, 0xF2, 0xFF, 0x00}, 
		{ 0xF1, 0xF3, 0xF1, 0x00}
	};
	
	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_get_mctp_ver_support) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr) + sizeof(versions);

	/* Initialize the buffers */
	memset(&ep_resp, 0, sizeof(ep_resp));

	/* Copy to Tx packet */
	memcpy(&ep_resp, &get_mctp_ver_support_resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support));
	memcpy(ep_resp.data, versions, sizeof(versions));

	mctp_print_resp_msg(&ep_resp, "MCTP_GET_MCTP_VER_SUPPORT_RESPONSE", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_resp,
		sizeof(struct mctp_ctrl_resp_get_mctp_ver_support) + sizeof(versions), hdr, &bind_id, pvt_binding,
		binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get message type support */
mctp_ret_codes_t mctp_responder_get_msg_type_support_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr, 
                       uint16_t remote_id, struct mctp_ctrl_cmd_get_msg_type_support *get_msg_type_support_req)
{
	mctp_requester_rc_t mctp_ret;

	struct mctp_ctrl_resp_get_msg_type_support get_msg_type_support_resp;
	struct mctp_ctrl_resp ep_resp;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;

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

	/* Encode get message type support message */
    memcpy(&get_msg_type_support_resp, get_msg_type_support_req, sizeof(struct mctp_ctrl_cmd_get_msg_type_support));
    get_msg_type_support_resp.ctrl_hdr.rq_dgram_inst &= ~ MCTP_CTRL_HDR_FLAG_REQUEST;
    get_msg_type_support_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
	get_msg_type_support_resp.msg_type_count = 1;

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_get_msg_type_support) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr) + 1;

	/* Initialize the buffers */
	memset(&ep_resp, 0, sizeof(ep_resp));

	/* Copy to Tx packet */
	memcpy(&ep_resp, &get_msg_type_support_resp, sizeof(struct mctp_ctrl_resp_get_msg_type_support));

	mctp_print_resp_msg(&ep_resp, "MCTP_GET_MSG_TYPE_RESPONSE", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_resp,
		sizeof(struct mctp_ctrl_resp_get_msg_type_support) + 1, hdr, &bind_id, pvt_binding,
		binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Send function for Get vendor message tyep support */
mctp_ret_codes_t mctp_responder_get_vdm_support_send_response(int sock_fd,
					   mctp_binding_ids_t bind_id, mctp_eid_t dest_eid, const uint8_t* hdr,
                       uint16_t remote_id, struct mctp_ctrl_cmd_get_vdm_support *get_vdm_support_req)
{
	mctp_requester_rc_t mctp_ret;

	struct mctp_ctrl_resp_get_vdm_support get_vdm_support_resp;
	struct mctp_ctrl_resp ep_resp;
	size_t msg_len;
	void *pvt_binding = NULL;
	struct mctp_astpcie_pkt_private pvt_binding_pcie;
	struct mctp_astspi_pkt_private pvt_binding_spi;
	size_t binding_size = 0;

	/* Set private binding */
	if (MCTP_BINDING_PCIE== bind_id) {
		pvt_binding_pcie.routing = PCIE_ROUTE_BY_ID;
		pvt_binding_pcie.remote_id = remote_id;
		pvt_binding = &pvt_binding_pcie;
		binding_size = sizeof(pvt_binding_pcie);
	} else if (MCTP_BINDING_SPI == bind_id) {
		memset(&pvt_binding_spi, 0, sizeof(pvt_binding_spi));
		pvt_binding = &pvt_binding_spi;
		binding_size = sizeof(pvt_binding_spi);
	}

	/* Encode get message type support message */
    memcpy(&get_vdm_support_resp, get_vdm_support_req, sizeof(struct mctp_ctrl_cmd_get_vdm_support));
    get_vdm_support_resp.ctrl_hdr.rq_dgram_inst &= ~ MCTP_CTRL_HDR_FLAG_REQUEST;
    get_vdm_support_resp.completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
	get_vdm_support_resp.vendor_id_data_iana = 0;

	/* Get the message length */
	msg_len = sizeof(struct mctp_ctrl_resp_get_vdm_support) -
		  sizeof(struct mctp_ctrl_cmd_msg_hdr);

	/* Initialize the buffers */
	memset(&ep_resp, 0, sizeof(ep_resp));

	/* Copy to Tx packet */
	memcpy(&ep_resp, &get_vdm_support_resp, sizeof(struct mctp_ctrl_resp_get_vdm_support));

	mctp_print_resp_msg(&ep_resp, "MCTP_GET_EP_VDM_SUPPORT_RESPONSE", msg_len);

	/* Send the request message over socket */
	mctp_ret = mctp_msg_client_with_binding_send(
		dest_eid, sock_fd, (const uint8_t *)&ep_resp,
		sizeof(struct mctp_ctrl_resp_get_vdm_support), hdr, &bind_id, pvt_binding,
		binding_size);

	if (mctp_ret == MCTP_REQUESTER_SEND_FAIL) {
		MCTP_SYS_ERR("%s: Failed to send message..\n", __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

/* Receive function for Get UUID */
int mctp_get_endpoint_uuid_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
				    size_t resp_msg_len)
{
	bool req_ret;
	struct mctp_ctrl_resp_get_uuid *uuid_resp;
	int ret;
	mctp_uuid_table_t uuid_table = { 0 };

	/* Trace the Rx message */
	mctp_print_resp_msg((struct mctp_ctrl_resp *)mctp_resp_msg,
			    "MCTP_GET_EP_UUID_RESPONSE",
			    resp_msg_len -
				    sizeof(struct mctp_ctrl_cmd_msg_hdr));

	uuid_resp = (struct mctp_ctrl_resp_get_uuid *)mctp_resp_msg;

	/* Parse the UUID response message */
	req_ret = mctp_decode_resp_get_uuid(uuid_resp);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet parsing failed\n", __func__);
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
		MCTP_SYS_ERR("%s: Failed to update global UUID table..\n",
			      __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}


/* Receive function for Get Messgae types */
int mctp_get_msg_type_response(mctp_eid_t eid, uint8_t *mctp_resp_msg,
			       size_t resp_msg_len)
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
		MCTP_SYS_ERR(
			"%s: Minimum message size is 5 bytes, but received %zi\n",
			__func__, resp_msg_len);
		return MCTP_RET_REQUEST_FAILED;
	}

	msg_type_resp =
		(struct mctp_ctrl_resp_get_msg_type_support *)mctp_resp_msg;

	/* Parse the Get message type buffer */
	req_ret = mctp_decode_ctrl_cmd_get_msg_type_support(msg_type_resp);
	if (req_ret == false) {
		MCTP_SYS_ERR("%s: Packet parsing failed\n", __func__);
		return MCTP_RET_ENCODE_FAILED;
	}

	MCTP_SYS_DEBUG("%s: EID: %d, Number of supported message types %d\n",
			__func__, eid,
			((struct mctp_ctrl_resp *)mctp_resp_msg)->data[0]);

	/* Update Message type private params to export to upper layer */
	msg_type_table.next = NULL;
	msg_type_table.old_enabled = false;
	msg_type_table.enabled = true;
	msg_type_table.new = true;
	msg_type_table.eid = eid;
	msg_type_table.data_len = ((struct mctp_ctrl_resp *)mctp_resp_msg)
					  ->data[MCTP_MSG_TYPE_DATA_LEN_OFFSET];
	memset(msg_type_table.slot, 0, sizeof(msg_type_table.slot));

	if (msg_type_table.data_len > (MCTP_BTU - 1)) {
		MCTP_SYS_INFO(
			"%s: EID: %d, Data length: %u, but in the response there is only: %zi\n",
			__func__, eid, msg_type_table.data_len, resp_msg_len);
		msg_type_table.data_len = MCTP_BTU - 1;
	}

	if (msg_type_table.data_len > (resp_msg_len - 5)) {
		MCTP_SYS_INFO(
			"%s: EID: %d, Data length: %u, but in the response there is only: %zi\n",
			__func__, eid, msg_type_table.data_len, resp_msg_len);
		msg_type_table.data_len = resp_msg_len - 5;
	}

	memcpy(&msg_type_table.data,
	       &((struct mctp_ctrl_resp *)mctp_resp_msg)
			->data[MCTP_MSG_TYPE_DATA_OFFSET],
	       msg_type_table.data_len);

	/* Create a new Msg type entry and add to list */
	ret = mctp_msg_type_entry_add(&msg_type_table);
	if (ret < 0) {
		MCTP_SYS_ERR("%s: Failed to update global routing table..\n",
			      __func__);
		return MCTP_RET_REQUEST_FAILED;
	}

	return MCTP_RET_REQUEST_SUCCESS;
}

