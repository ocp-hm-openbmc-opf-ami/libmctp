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

static void encode_ctrl_cmd_header(struct mctp_ctrl_msg_hdr *mctp_ctrl_hdr,
				   uint8_t rq_dgram_inst, uint8_t cmd_code)
{
	mctp_ctrl_hdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	mctp_ctrl_hdr->rq_dgram_inst = rq_dgram_inst;
	mctp_ctrl_hdr->command_code = cmd_code;
}

encode_decode_api_return_code mctp_encode_ctrl_cmd_resolve_eid_req_new(
	struct mctp_ctrl_cmd_resolve_eid_req *resolve_eid_cmd,
	uint8_t rq_dgram_inst, uint8_t target_eid)
{
	if (!resolve_eid_cmd)
		return INPUT_ERROR;

	encode_ctrl_cmd_header(&resolve_eid_cmd->ctrl_msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	resolve_eid_cmd->target_eid = target_eid;
	return ENCODE_SUCCESS;
}