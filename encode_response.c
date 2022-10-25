#include <stdlib.h>
#include <string.h>

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

encode_rc mctp_encode_resolve_eid_resp(struct mctp_msg *response,
				       const size_t length,
				       uint8_t rq_dgram_inst,
				       uint8_t bridge_eid,
				       struct variable_field *address)
{
	if (response == NULL || address == NULL)
		return ENCODE_INPUT_ERROR;
	if (length <
	    sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) + address->data_size)
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	struct mctp_ctrl_cmd_resolve_eid_resp *resp =
		(struct mctp_ctrl_cmd_resolve_eid_resp *)(response);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->bridge_eid = bridge_eid;
	if (address->data != NULL) {
		memcpy(resp->physical_address, address->data,
		       address->data_size);
	} else {
		return ENCODE_GENERIC_ERROR;
	}
	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_allocate_endpoint_id_resp(
	struct mctp_msg *response, const size_t length, uint8_t rq_dgram_inst,
	mctp_ctrl_cmd_allocate_eids_resp_op op, uint8_t eid_pool_size,
	uint8_t first_eid)
{
	if (response == NULL)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_allocate_eids_resp))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	struct mctp_ctrl_cmd_allocate_eids_resp *resp =
		(struct mctp_ctrl_cmd_allocate_eids_resp *)(response);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->operation = op;
	resp->eid_pool_size = eid_pool_size;
	resp->first_eid = first_eid;
	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_set_eid_resp(struct mctp_msg *response,
				   const size_t length, uint8_t rq_dgram_inst,
				   uint8_t eid_pool_size, uint8_t status,
				   mctp_eid_t eid_set)
{
	if (response == NULL)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_resp_set_eid))
		return ENCODE_GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	struct mctp_ctrl_resp_set_eid *resp =
		(struct mctp_ctrl_resp_set_eid *)(response);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->eid_pool_size = eid_pool_size;
	resp->status = status;
	resp->eid_set = eid_set;
	return ENCODE_SUCCESS;
}

encode_rc mctp_encode_get_uuid_resp(struct mctp_msg *response,
				    const size_t length, uint8_t rq_dgram_inst,
				    const guid_t *uuid)
{
	if (response == NULL || uuid == NULL)
		return ENCODE_INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_resp_get_uuid))
		return ENCODE_GENERIC_ERROR;

	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	struct mctp_ctrl_resp_get_uuid *resp =
		(struct mctp_ctrl_resp_get_uuid *)(response);

	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->uuid = *uuid;

	return ENCODE_SUCCESS;
}