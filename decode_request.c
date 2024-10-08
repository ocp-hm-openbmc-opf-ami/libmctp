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

encode_decode_rc mctp_decode_resolve_eid_req(const struct mctp_msg *request,
					     const size_t length,
					     struct mctp_ctrl_msg_hdr *ctrl_hdr,
					     uint8_t *target_eid)
{
	if (request == NULL || ctrl_hdr == NULL || target_eid == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_cmd_resolve_eid_req))
		return GENERIC_ERROR;
	if (request->msg_hdr.command_code != MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID)
		return GENERIC_ERROR;
	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	struct mctp_ctrl_cmd_resolve_eid_req *req =
		(struct mctp_ctrl_cmd_resolve_eid_req *)(request);
	*target_eid = req->target_eid;
	return SUCCESS;
}

encode_decode_rc
mctp_decode_allocate_endpoint_id_req(const struct mctp_msg *request,
				     const size_t length,
				     struct mctp_ctrl_msg_hdr *ctrl_hdr,
				     mctp_ctrl_cmd_allocate_eids_req_op *op,
				     uint8_t *eid_pool_size, uint8_t *first_eid)
{
	if (request == NULL || ctrl_hdr == NULL || op == NULL ||
	    eid_pool_size == NULL || first_eid == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_cmd_allocate_eids_req))
		return GENERIC_ERROR;
	if (request->msg_hdr.command_code !=
	    MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	struct mctp_ctrl_cmd_allocate_eids_req *req =
		(struct mctp_ctrl_cmd_allocate_eids_req *)(request);
	*op = req->operation;
	*eid_pool_size = req->eid_pool_size;
	*first_eid = req->first_eid;
	return SUCCESS;
}

encode_decode_rc mctp_decode_set_eid_req(const struct mctp_msg *request,
					 const size_t length,
					 struct mctp_ctrl_msg_hdr *ctrl_hdr,
					 mctp_ctrl_cmd_set_eid_op *op,
					 uint8_t *eid)
{
	if (request == NULL || ctrl_hdr == NULL || op == NULL || eid == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_cmd_set_eid))
		return GENERIC_ERROR;
	if (request->msg_hdr.command_code != MCTP_CTRL_CMD_SET_ENDPOINT_ID)
		return GENERIC_ERROR;
	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	struct mctp_ctrl_cmd_set_eid *req =
		(struct mctp_ctrl_cmd_set_eid *)request;
	*op = req->operation;
	*eid = req->eid;
	return SUCCESS;
}

encode_decode_rc mctp_decode_get_uuid_req(const struct mctp_msg *request,
					  const size_t length,
					  struct mctp_ctrl_msg_hdr *ctrl_hdr)
{
	if (request == NULL || ctrl_hdr == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_cmd_get_uuid))
		return GENERIC_ERROR;
	if (request->msg_hdr.command_code != MCTP_CTRL_CMD_GET_ENDPOINT_UUID)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	return SUCCESS;
}

encode_decode_rc
mctp_decode_get_networkid_req(const struct mctp_msg *request,
			      const size_t length,
			      struct mctp_ctrl_msg_hdr *ctrl_hdr)
{
	if (request == NULL || ctrl_hdr == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_networkid_req))
		return GENERIC_ERROR;
	if (request->msg_hdr.command_code != MCTP_CTRL_CMD_GET_NETWORK_ID)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	return SUCCESS;
}

encode_decode_rc mctp_decode_get_routing_table_req(
	const struct mctp_msg *request, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *entry_handle)
{
	if (request == NULL || ctrl_hdr == NULL || entry_handle == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_routing_table_req))
		return GENERIC_ERROR;
	if (request->msg_hdr.command_code !=
	    MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	struct mctp_ctrl_cmd_get_routing_table_req *req =
		(struct mctp_ctrl_cmd_get_routing_table_req *)request;
	*entry_handle = req->entry_handle;
	return SUCCESS;
}

encode_decode_rc mctp_decode_get_ver_support_req(
	const struct mctp_msg *request, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *msg_type_number)
{
	if (request == NULL || ctrl_hdr == NULL || msg_type_number == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support))
		return GENERIC_ERROR;
	if (request->msg_hdr.command_code != MCTP_CTRL_CMD_GET_VERSION_SUPPORT)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	struct mctp_ctrl_cmd_get_mctp_ver_support *req =
		(struct mctp_ctrl_cmd_get_mctp_ver_support *)request;
	*msg_type_number = req->msg_type_number;
	return SUCCESS;
}

encode_decode_rc mctp_decode_get_eid_req(const struct mctp_msg *request,
					 const size_t length,
					 struct mctp_ctrl_msg_hdr *ctrl_hdr)
{
	if (request == NULL || ctrl_hdr == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_get_eid))
		return GENERIC_ERROR;
	if (request->msg_hdr.command_code != MCTP_CTRL_CMD_GET_ENDPOINT_ID)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	return SUCCESS;
}

encode_decode_rc mctp_decode_get_vdm_support_req(
	const struct mctp_msg *request, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *vid_set_selector)
{
	if (request == NULL || ctrl_hdr == NULL || vid_set_selector == NULL)
		return INPUT_ERROR;

	if (length != sizeof(struct mctp_ctrl_cmd_get_vdm_support))
		return GENERIC_ERROR;

	if (request->msg_hdr.command_code !=
	    MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	struct mctp_ctrl_cmd_get_vdm_support *req =
		(struct mctp_ctrl_cmd_get_vdm_support *)request;
	*vid_set_selector = req->vendor_id_set_selector;
	return SUCCESS;
}

encode_decode_rc
mctp_decode_prepare_endpoint_discovery_req(const struct mctp_msg *request,
					   const size_t length,
					   struct mctp_ctrl_msg_hdr *ctrl_hdr)
{
	if (request == NULL || ctrl_hdr == NULL)
		return INPUT_ERROR;

	if (length !=
	    sizeof(struct mctp_ctrl_cmd_prepare_for_endpoint_discovery))
		return GENERIC_ERROR;

	if (request->msg_hdr.command_code !=
	    MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&request->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	return SUCCESS;
}
