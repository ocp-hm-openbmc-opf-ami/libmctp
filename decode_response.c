#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp.h"
#include "libmctp-cmds.h"

static void decode_ctrl_cmd_header(struct mctp_ctrl_msg_hdr *mctp_ctrl_hdr,
				   uint8_t *ic_msg_type, uint8_t *rq_dgram_inst,
				   uint8_t *cmd_code)
{
	if (mctp_ctrl_hdr == NULL || ic_msg_type == NULL ||
	    rq_dgram_inst == NULL || cmd_code == NULL)
		return;
	*ic_msg_type = mctp_ctrl_hdr->ic_msg_type;
	*rq_dgram_inst = mctp_ctrl_hdr->rq_dgram_inst;
	*cmd_code = mctp_ctrl_hdr->command_code;
}

encode_decode_api_return_code
mctp_decode_resolve_eid_resp(struct mctp_msg *response, size_t length,
			     struct mctp_ctrl_msg_hdr *ctrl_hdr,
			     uint8_t *completion_code, uint8_t *bridge_eid,
			     struct variable_field *address)
{
	if (response == NULL || ctrl_hdr == NULL || bridge_eid == NULL ||
	    completion_code == NULL || address == NULL)
		return INPUT_ERROR;

	decode_ctrl_cmd_header(&response->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	struct mctp_ctrl_cmd_resolve_eid_resp *resp =
		(struct mctp_ctrl_cmd_resolve_eid_resp *)(response);
	if (resp->ctrl_msg_hdr.command_code !=
	    MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID)
		return GENERIC_ERROR;
	*completion_code = resp->completion_code;
	if (resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return CC_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_resolve_eid_resp))
		return GENERIC_ERROR;
	*bridge_eid = resp->bridge_eid;
	address->data =
		(uint8_t *)resp + sizeof(struct mctp_ctrl_cmd_resolve_eid_resp);
	address->data_size =
		length - sizeof(struct mctp_ctrl_cmd_resolve_eid_resp);
	return DECODE_SUCCESS;
}

encode_decode_api_return_code mctp_decode_allocate_endpoint_id_resp(
	struct mctp_msg *response, size_t length, uint8_t *ic_msg_type,
	uint8_t *rq_dgram_inst, uint8_t *command_code, uint8_t *cc,
	mctp_ctrl_cmd_allocate_eids_resp_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid)
{
	if (response == NULL || ic_msg_type == NULL || rq_dgram_inst == NULL ||
	    command_code == NULL || cc == NULL || op == NULL ||
	    eid_pool_size == NULL || first_eid == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_allocate_eids_resp))
		return GENERIC_ERROR;
	decode_ctrl_cmd_header(&response->msg_hdr, ic_msg_type, rq_dgram_inst,
			       command_code);
	struct mctp_ctrl_cmd_allocate_eids_resp *resp =
		(struct mctp_ctrl_cmd_allocate_eids_resp *)(response);
	*cc = resp->completion_code;
	*op = resp->operation;
	*eid_pool_size = resp->eid_pool_size;
	*first_eid = resp->first_eid;

	return DECODE_SUCCESS;
}