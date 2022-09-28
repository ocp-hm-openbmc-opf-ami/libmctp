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
mctp_decode_resolve_eid_req(struct mctp_msg *request, size_t length,
			    struct mctp_ctrl_msg_hdr *ctrl_hdr,
			    uint8_t *target_eid)
{
	if (request == NULL || ctrl_hdr == NULL || target_eid == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_resolve_eid_req))
		return GENERIC_ERROR;
	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	struct mctp_ctrl_cmd_resolve_eid_req *req =
		(struct mctp_ctrl_cmd_resolve_eid_req *)(request);
	if (req->ctrl_msg_hdr.command_code != MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID)
		return GENERIC_ERROR;
	*target_eid = req->target_eid;
	return DECODE_SUCCESS;
}

encode_decode_api_return_code mctp_decode_allocate_endpoint_id_req(
	struct mctp_msg *request, size_t length, uint8_t *ic_msg_type,
	uint8_t *rq_dgram_inst, uint8_t *command_code,
	mctp_ctrl_cmd_allocate_eids_req_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid)
{
	if (request == NULL || ic_msg_type == NULL || rq_dgram_inst == NULL ||
	    command_code == NULL || op == NULL || eid_pool_size == NULL ||
	    first_eid == NULL)
		return INPUT_ERROR;

	if (length < sizeof(struct mctp_ctrl_cmd_allocate_eids_req))
		return GENERIC_ERROR;
	decode_ctrl_cmd_header(&request->msg_hdr, ic_msg_type, rq_dgram_inst,
			       command_code);

	struct mctp_ctrl_cmd_allocate_eids_req *req =
		(struct mctp_ctrl_cmd_allocate_eids_req *)(request);
	*op = req->operation;
	*eid_pool_size = req->eid_pool_size;
	*first_eid = req->first_eid;
	return DECODE_SUCCESS;
}

encode_decode_api_return_code
mctp_decode_set_eid_req(struct mctp_msg *request, size_t length,
			struct mctp_ctrl_msg_hdr *ctrl_hdr,
			mctp_ctrl_cmd_set_eid_op *op, uint8_t *eid)
{
	if (request == NULL || ctrl_hdr == NULL || op == NULL || eid == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_set_eid))
		return GENERIC_ERROR;
	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	struct mctp_ctrl_cmd_set_eid *req =
		(struct mctp_ctrl_cmd_set_eid *)request;
	*op = req->operation;
	*eid = req->eid;
	return DECODE_SUCCESS;
}