#include <stdlib.h>

#include "libmctp.h"
#include "libmctp-cmds.h"

static void
decode_ctrl_cmd_header(const struct mctp_ctrl_msg_hdr *mctp_ctrl_hdr,
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

decode_rc mctp_decode_resolve_eid_req(const struct mctp_msg *request,
				      const size_t length,
				      struct mctp_ctrl_msg_hdr *ctrl_hdr,
				      uint8_t *target_eid)
{
	if (request == NULL || ctrl_hdr == NULL || target_eid == NULL)
		return DECODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_resolve_eid_req))
		return DECODE_GENERIC_ERROR;
	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	if (ctrl_hdr->command_code != MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID)
		return DECODE_GENERIC_ERROR;
	struct mctp_ctrl_cmd_resolve_eid_req *req =
		(struct mctp_ctrl_cmd_resolve_eid_req *)(request);
	*target_eid = req->target_eid;
	return DECODE_SUCCESS;
}

decode_rc
mctp_decode_allocate_endpoint_id_req(const struct mctp_msg *request,
				     const size_t length,
				     struct mctp_ctrl_msg_hdr *ctrl_hdr,
				     mctp_ctrl_cmd_allocate_eids_req_op *op,
				     uint8_t *eid_pool_size, uint8_t *first_eid)
{
	if (request == NULL || ctrl_hdr == NULL || op == NULL ||
	    eid_pool_size == NULL || first_eid == NULL)
		return DECODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_allocate_eids_req))
		return DECODE_GENERIC_ERROR;
	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	if (ctrl_hdr->command_code != MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS)
		return DECODE_GENERIC_ERROR;
	struct mctp_ctrl_cmd_allocate_eids_req *req =
		(struct mctp_ctrl_cmd_allocate_eids_req *)(request);
	*op = req->operation;
	*eid_pool_size = req->eid_pool_size;
	*first_eid = req->first_eid;
	return DECODE_SUCCESS;
}

decode_rc mctp_decode_set_eid_req(const struct mctp_msg *request,
				  const size_t length,
				  struct mctp_ctrl_msg_hdr *ctrl_hdr,
				  mctp_ctrl_cmd_set_eid_op *op, uint8_t *eid)
{
	if (request == NULL || ctrl_hdr == NULL || op == NULL || eid == NULL)
		return DECODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_set_eid))
		return DECODE_GENERIC_ERROR;
	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	if (ctrl_hdr->command_code != MCTP_CTRL_CMD_SET_ENDPOINT_ID)
		return DECODE_GENERIC_ERROR;

	struct mctp_ctrl_cmd_set_eid *req =
		(struct mctp_ctrl_cmd_set_eid *)request;
	*op = req->operation;
	*eid = req->eid;
	return DECODE_SUCCESS;
}

decode_rc
mctp_decode_get_networkid_req(struct mctp_msg *request, size_t length,
			      struct mctp_ctrl_msg_hdr *ctrl_hdr)
{
	if (request == NULL || ctrl_hdr == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_networkid_req))
		return GENERIC_ERROR;

	struct mctp_ctrl_cmd_get_networkid_req *req =
		(struct mctp_ctrl_cmd_get_networkid_req *)request;
	if (req->ctrl_msg_hdr.command_code != MCTP_CTRL_CMD_GET_NETWORK_ID)
		return GENERIC_ERROR;

	*ctrl_hdr = req->ctrl_msg_hdr;
  	return DECODE_SUCCESS;
}

decode_rc mctp_decode_get_uuid_req(const struct mctp_msg *request,
				   const size_t length,
				   struct mctp_ctrl_msg_hdr *ctrl_hdr)
{
	if (request == NULL || ctrl_hdr == NULL)
		return DECODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_uuid))
		return DECODE_GENERIC_ERROR;

	struct mctp_ctrl_cmd_get_uuid *req =
		(struct mctp_ctrl_cmd_get_uuid *)request;

	*ctrl_hdr = req->ctrl_msg_hdr;
	if (ctrl_hdr->command_code != MCTP_CTRL_CMD_GET_ENDPOINT_UUID)
		return DECODE_GENERIC_ERROR;
	return DECODE_SUCCESS;
}
