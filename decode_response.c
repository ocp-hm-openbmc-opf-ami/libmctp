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

encode_decode_rc mctp_decode_resolve_eid_resp(
	const struct mctp_msg *response, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *completion_code,
	uint8_t *bridge_eid, struct variable_field *address)
{
	if (response == NULL || ctrl_hdr == NULL || bridge_eid == NULL ||
	    completion_code == NULL || address == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_cmd_resolve_eid_resp))
		return GENERIC_ERROR;
	if (response->msg_hdr.command_code != MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&response->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	struct mctp_ctrl_cmd_resolve_eid_resp *resp =
		(struct mctp_ctrl_cmd_resolve_eid_resp *)(response);
	*completion_code = resp->completion_code;
	if (resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return CC_ERROR;

	*bridge_eid = resp->bridge_eid;
	address->data = resp->physical_address;
	address->data_size =
		length - sizeof(struct mctp_ctrl_cmd_resolve_eid_resp);
	return SUCCESS;
}

encode_decode_rc mctp_decode_allocate_endpoint_id_resp(
	const struct mctp_msg *response, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *completion_code,
	mctp_ctrl_cmd_allocate_eids_resp_op *op, uint8_t *eid_pool_size,
	uint8_t *first_eid)
{
	if (response == NULL || ctrl_hdr == NULL || completion_code == NULL ||
	    op == NULL || eid_pool_size == NULL || first_eid == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_cmd_allocate_eids_resp))
		return GENERIC_ERROR;
	if (response->msg_hdr.command_code !=
	    MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&response->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	struct mctp_ctrl_cmd_allocate_eids_resp *resp =
		(struct mctp_ctrl_cmd_allocate_eids_resp *)(response);

	*completion_code = resp->completion_code;
	if (resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return CC_ERROR;
	*op = resp->operation;
	*eid_pool_size = resp->eid_pool_size;
	*first_eid = resp->first_eid;

	return SUCCESS;
}

encode_decode_rc mctp_decode_set_eid_resp(const struct mctp_msg *response,
					  const size_t length,
					  struct mctp_ctrl_msg_hdr *ctrl_hdr,
					  uint8_t *completion_code,
					  uint8_t *eid_pool_size,
					  uint8_t *status, mctp_eid_t *eid_set)
{
	if (response == NULL || ctrl_hdr == NULL || completion_code == NULL ||
	    eid_pool_size == NULL || status == NULL || eid_set == NULL)
		return INPUT_ERROR;

	if (length != sizeof(struct mctp_ctrl_resp_set_eid))
		return GENERIC_ERROR;
	if (response->msg_hdr.command_code != MCTP_CTRL_CMD_SET_ENDPOINT_ID)
		return GENERIC_ERROR;
	decode_ctrl_cmd_header(&response->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	struct mctp_ctrl_resp_set_eid *resp =
		(struct mctp_ctrl_resp_set_eid *)(response);

	*completion_code = resp->completion_code;
	if (resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return CC_ERROR;
	*eid_pool_size = resp->eid_pool_size;
	*status = resp->status;
	*eid_set = resp->eid_set;
	return SUCCESS;
}

encode_decode_rc mctp_decode_get_uuid_resp(const struct mctp_msg *response,
					   const size_t length,
					   struct mctp_ctrl_msg_hdr *ctrl_hdr,
					   uint8_t *completion_code,
					   guid_t *uuid)
{
	if (response == NULL || completion_code == NULL || uuid == NULL ||
	    ctrl_hdr == NULL)
		return INPUT_ERROR;
	if (length != sizeof(struct mctp_ctrl_resp_get_uuid))
		return GENERIC_ERROR;
	struct mctp_ctrl_resp_get_uuid *resp =
		(struct mctp_ctrl_resp_get_uuid *)(response);
	if (response->msg_hdr.command_code != MCTP_CTRL_CMD_GET_ENDPOINT_UUID)
		return GENERIC_ERROR;
	decode_ctrl_cmd_header(&response->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	*completion_code = resp->completion_code;
	if (resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return CC_ERROR;
	*uuid = resp->uuid;
	return SUCCESS;
}

encode_decode_rc
mctp_decode_get_networkid_resp(const struct mctp_msg *response,
			       const size_t length,
			       struct mctp_ctrl_msg_hdr *ctrl_hdr,
			       uint8_t *completion_code, guid_t *network_id)
{
	if (response == NULL || ctrl_hdr == NULL || completion_code == NULL ||
	    network_id == NULL)
		return INPUT_ERROR;

	if (length < sizeof(struct mctp_ctrl_get_networkid_resp))
		return GENERIC_ERROR;
	if (response->msg_hdr.command_code != MCTP_CTRL_CMD_GET_NETWORK_ID)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&response->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	struct mctp_ctrl_get_networkid_resp *resp =
		(struct mctp_ctrl_get_networkid_resp *)(response);

	*completion_code = resp->completion_code;
	if (resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return CC_ERROR;
	*network_id = resp->networkid;
	return SUCCESS;
}

encode_decode_rc mctp_decode_get_ver_support_resp(
	const struct mctp_msg *response, const size_t length,
	struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t *completion_code,
	uint8_t *number_of_entries, struct version_entry *vers,
	const size_t verslen)
{
	if (response == NULL || ctrl_hdr == NULL || completion_code == NULL ||
	    number_of_entries == NULL || vers == NULL)
		return INPUT_ERROR;
	if (length < sizeof(struct mctp_ctrl_resp_get_mctp_ver_support))
		return GENERIC_ERROR;
	if (response->msg_hdr.command_code != MCTP_CTRL_CMD_GET_VERSION_SUPPORT)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&response->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);

	struct mctp_ctrl_resp_get_mctp_ver_support *resp =
		(struct mctp_ctrl_resp_get_mctp_ver_support *)response;

	*completion_code = resp->completion_code;
	if (resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return CC_ERROR;
	*number_of_entries = resp->number_of_entries;
	if (verslen < *number_of_entries)
		return GENERIC_ERROR;
	if (*number_of_entries > 0)
		vers[0] = resp->version;
	for (int i = 0; i < *number_of_entries - 1; i++)
		vers[i + 1] = resp->versions[i];

	return SUCCESS;
}

encode_decode_rc mctp_decode_get_eid_resp(const struct mctp_msg *response,
					  const size_t length,
					  struct mctp_ctrl_msg_hdr *ctrl_hdr,
					  uint8_t *completion_code,
					  mctp_eid_t *eid, uint8_t *eid_type,
					  uint8_t *medium_data)
{
	if (response == NULL || ctrl_hdr == NULL || completion_code == NULL ||
	    eid == NULL || eid_type == NULL || medium_data == NULL)
		return INPUT_ERROR;

	if (length < sizeof(struct mctp_ctrl_resp_get_eid))
		return GENERIC_ERROR;
	if (response->msg_hdr.command_code != MCTP_CTRL_CMD_GET_ENDPOINT_ID)
		return GENERIC_ERROR;

	decode_ctrl_cmd_header(&response->msg_hdr, &ctrl_hdr->ic_msg_type,
			       &ctrl_hdr->rq_dgram_inst,
			       &ctrl_hdr->command_code);
	struct mctp_ctrl_resp_get_eid *resp =
		(struct mctp_ctrl_resp_get_eid *)(response);

	*completion_code = resp->completion_code;
	if (resp->completion_code != MCTP_CTRL_CC_SUCCESS)
		return CC_ERROR;
	*eid = resp->eid;
	*eid_type = resp->eid_type;
	*medium_data = resp->medium_data;
	return SUCCESS;
}
