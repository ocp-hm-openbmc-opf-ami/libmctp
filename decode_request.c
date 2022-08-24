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

encode_decode_api_return_code mctp_decode_resolve_eid_req(
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

encode_decode_api_return_code mctp_decode_allocate_endpoint_id_req(
	struct mctp_ctrl_cmd_allocate_eids_req *request, uint8_t *ic_msg_type,
	uint8_t *rq_dgram_inst, uint8_t *command_code,
	mctp_ctrl_cmd_allocate_eids_req_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid)
{
	if (request == NULL || ic_msg_type == NULL || rq_dgram_inst == NULL ||
	    command_code == NULL || op == NULL || eid_pool_size == NULL ||
	    first_eid == NULL)
		return INPUT_ERROR;
	decode_ctrl_cmd_header(&request->ctrl_msg_hdr, ic_msg_type,
			       rq_dgram_inst, command_code);
	*op = request->operation;
	*eid_pool_size = request->eid_pool_size;
	*first_eid = request->first_eid;

	return DECODE_SUCCESS;
}