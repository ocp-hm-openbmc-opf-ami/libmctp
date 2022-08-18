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

encode_decode_api_return_code mctp_decode_ctrl_cmd_resolve_eid_req_new(
	struct mctp_ctrl_cmd_resolve_eid_req *resolve_eid_cmd,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *target_eid)
{
	if (resolve_eid_cmd == NULL || ctrl_hdr == NULL || target_eid == NULL)
		return INPUT_ERROR;
	decode_ctrl_cmd_header(&resolve_eid_cmd->ctrl_msg_hdr,
			       &ctrl_hdr->ic_msg_type, &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	if (resolve_eid_cmd->ctrl_msg_hdr.command_code !=
	    MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID)
		return GENERIC_ERROR;
	*target_eid = resolve_eid_cmd->target_eid;
	return DECODE_SUCCESS;
}