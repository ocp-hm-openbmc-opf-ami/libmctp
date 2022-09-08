#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp.h"
#include "libmctp-cmds.h"

static void encode_ctrl_cmd_header(struct mctp_ctrl_msg_hdr *mctp_ctrl_hdr,
				   uint8_t rq_dgram_inst, uint8_t cmd_code)
{
	mctp_ctrl_hdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	mctp_ctrl_hdr->rq_dgram_inst = rq_dgram_inst;
	mctp_ctrl_hdr->command_code = cmd_code;
}

encode_decode_api_return_code
mctp_encode_resolve_eid_resp(struct mctp_msg *response, size_t length,
			     uint8_t rq_dgram_inst, uint8_t bridge_eid,
			     struct variable_field *address)
{
	if (response == NULL || address == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_resolve_eid_resp))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	struct mctp_ctrl_cmd_resolve_eid_resp *resp =
		(struct mctp_ctrl_cmd_resolve_eid_resp *)(response);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->bridge_eid = bridge_eid;
	memcpy(resp->physical_address, address->data, address->data_size);
	return ENCODE_SUCCESS;
}

encode_decode_api_return_code
mctp_encode_allocate_endpoint_id_resp(struct mctp_msg *response, size_t length,
				      struct mctp_ctrl_msg_hdr *ctrl_hdr,
				      mctp_ctrl_cmd_allocate_eids_resp_op op,
				      uint8_t eid_pool_size, uint8_t first_eid)
{
	if (response == NULL || ctrl_hdr == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_allocate_eids_resp))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, ctrl_hdr->rq_dgram_inst,
			       ctrl_hdr->command_code);
	struct mctp_ctrl_cmd_allocate_eids_resp *resp =
		(struct mctp_ctrl_cmd_allocate_eids_resp *)(response);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->operation = op;
	resp->eid_pool_size = eid_pool_size;
	resp->first_eid = first_eid;

	return ENCODE_SUCCESS;
}