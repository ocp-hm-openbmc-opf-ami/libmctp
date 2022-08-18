#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/errno-base.h>

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
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

encode_decode_api_return_code mctp_decode_ctrl_cmd_resolve_eid_resp_new(
	struct mctp_ctrl_cmd_resolve_eid_resp *response, size_t resp_size,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *completion_code,
	uint8_t *bridge_eid, struct variable_field *address)
{
	if (response == NULL || ctrl_hdr == NULL || bridge_eid == NULL ||
	    completion_code == NULL || address == NULL)
		return INPUT_ERROR;
	decode_ctrl_cmd_header(&response->ctrl_msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	if (response->ctrl_msg_hdr.command_code !=
	    MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID)
		return GENERIC_ERROR;

	*completion_code = response->completion_code;
	if (response->completion_code != MCTP_CTRL_CC_SUCCESS)
		return CC_ERROR;
	if (resp_size < sizeof(struct mctp_ctrl_cmd_resolve_eid_resp))
		return GENERIC_ERROR;
	*bridge_eid = response->bridge_eid;
	address->data = (uint8_t *)response +
			sizeof(struct mctp_ctrl_cmd_resolve_eid_resp);
	address->data_size =
		resp_size - sizeof(struct mctp_ctrl_cmd_resolve_eid_resp);
	return DECODE_SUCCESS;
}
