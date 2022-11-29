#include <stdlib.h>

#include "libmctp.h"
#include "libmctp-cmds.h"

static void encode_ctrl_cmd_header(struct mctp_ctrl_msg_hdr *mctp_ctrl_hdr,
				   uint8_t rq_dgram_inst, uint8_t cmd_code)
{
	if (mctp_ctrl_hdr == NULL)
		return;
	mctp_ctrl_hdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	mctp_ctrl_hdr->rq_dgram_inst = rq_dgram_inst;
	mctp_ctrl_hdr->command_code = cmd_code;
}

encode_rc mctp_encode_resolve_eid_req(struct mctp_msg *request,
				      const size_t length,
				      uint8_t rq_dgram_inst, uint8_t target_eid)
{
	if (!request)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_resolve_eid_req))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	struct mctp_ctrl_cmd_resolve_eid_req *req =
		(struct mctp_ctrl_cmd_resolve_eid_req *)(request);
	req->target_eid = target_eid;
	return ENCODE_SUCCESS;
}

encode_rc
mctp_encode_allocate_endpoint_id_req(struct mctp_msg *request,
				     const size_t length, uint8_t rq_dgram_inst,
				     mctp_ctrl_cmd_allocate_eids_req_op op,
				     uint8_t pool_size, uint8_t starting_eid)
{
	if (!request)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_allocate_eids_req))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	struct mctp_ctrl_cmd_allocate_eids_req *req =
		(struct mctp_ctrl_cmd_allocate_eids_req *)(request);
	req->operation = op;
	req->eid_pool_size = pool_size;
	req->first_eid = starting_eid;
	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_set_eid_req(struct mctp_msg *request, const size_t length,
				  uint8_t rq_dgram_inst,
				  mctp_ctrl_cmd_set_eid_op op, uint8_t eid)
{
	if (!request)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_set_eid))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	struct mctp_ctrl_cmd_set_eid *req =
		(struct mctp_ctrl_cmd_set_eid *)request;
	req->operation = op;
	req->eid = eid;
	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_get_uuid_req(struct mctp_msg *request,
				   const size_t length, uint8_t rq_dgram_inst)
{
	if (!request)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_uuid))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);

	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_get_networkid_req(struct mctp_msg *request,
					const size_t length,
					uint8_t rq_dgram_inst)
{
	if (!request)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_networkid_req))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_NETWORK_ID);
	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_get_routing_table_req(struct mctp_msg *request,
					    const size_t length,
					    uint8_t rq_dgram_inst,
					    uint8_t entry_handle)
{
	if (!request)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_routing_table_req))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES);
	struct mctp_ctrl_cmd_get_routing_table_req *req =
		(struct mctp_ctrl_cmd_get_routing_table_req *)request;
	req->entry_handle = entry_handle;
	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_get_ver_support_req(struct mctp_msg *request,
					  const size_t length,
					  uint8_t rq_dgram_inst,
					  uint8_t msg_type_number)
{
	if (!request)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);

	struct mctp_ctrl_cmd_get_mctp_ver_support *req =
		(struct mctp_ctrl_cmd_get_mctp_ver_support *)request;
	req->msg_type_number = msg_type_number;
	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_get_eid_req(struct mctp_msg *request, const size_t length,
				  uint8_t rq_dgram_inst)
{
	if (!request)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_eid))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ENDPOINT_ID);

	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_discovery_notify_req(struct mctp_msg *request,
					   const size_t length,
					   uint8_t rq_dgram_inst)
{
	if (!request)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_discovery_notify))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&request->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_DISCOVERY_NOTIFY);

	return ENCODE_SUCCESS;
}
