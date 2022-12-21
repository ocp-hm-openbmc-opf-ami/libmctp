#include <stdlib.h>

#include "libmctp.h"
#include "libmctp-cmds.h"

static void encode_ctrl_cmd_header(struct mctp_ctrl_msg_hdr *mctp_ctrl_hdr,
				   const uint8_t rq_dgram_inst, const uint8_t cmd_code)
{
	if (mctp_ctrl_hdr == NULL)
		return;
	mctp_ctrl_hdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	mctp_ctrl_hdr->rq_dgram_inst = rq_dgram_inst;
	mctp_ctrl_hdr->command_code = cmd_code;
}

encode_decode_rc mctp_encode_resolve_eid_req(struct mctp_msg *request,
					     const size_t length,
					     uint8_t rq_dgram_inst,
					     uint8_t target_eid)
{
	if (request == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_cmd_resolve_eid_req))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	struct mctp_ctrl_cmd_resolve_eid_req *req =
		(struct mctp_ctrl_cmd_resolve_eid_req *)(request);
	req->target_eid = target_eid;
	return SUCCESS;
}

encode_decode_rc
mctp_encode_allocate_endpoint_id_req(struct mctp_msg *request,
				     const size_t length, uint8_t rq_dgram_inst,
				     mctp_ctrl_cmd_allocate_eids_req_op op,
				     uint8_t pool_size, uint8_t starting_eid)
{
	if (request == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_cmd_allocate_eids_req))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	struct mctp_ctrl_cmd_allocate_eids_req *req =
		(struct mctp_ctrl_cmd_allocate_eids_req *)(request);
	req->operation = op;
	req->eid_pool_size = pool_size;
	req->first_eid = starting_eid;
	return SUCCESS;
}

encode_decode_rc mctp_encode_set_eid_req(struct mctp_msg *request,
					 const size_t length,
					 uint8_t rq_dgram_inst,
					 mctp_ctrl_cmd_set_eid_op op,
					 uint8_t eid)
{
	if (request == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_cmd_set_eid))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	struct mctp_ctrl_cmd_set_eid *req =
		(struct mctp_ctrl_cmd_set_eid *)request;
	req->operation = op;
	req->eid = eid;
	return SUCCESS;
}

encode_decode_rc mctp_encode_get_uuid_req(struct mctp_msg *request,
					  const size_t length,
					  uint8_t rq_dgram_inst)
{
	if (request == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_cmd_get_uuid))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);

	return SUCCESS;
}
