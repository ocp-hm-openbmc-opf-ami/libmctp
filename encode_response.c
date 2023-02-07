#include <stdlib.h>
#include <string.h>

#include "libmctp.h"
#include "libmctp-cmds.h"

static void encode_ctrl_cmd_header(struct mctp_ctrl_msg_hdr *mctp_ctrl_hdr,
				   const uint8_t rq_dgram_inst,
				   const uint8_t cmd_code)
{
	if (mctp_ctrl_hdr == NULL)
		return;
	mctp_ctrl_hdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	mctp_ctrl_hdr->rq_dgram_inst = rq_dgram_inst;
	mctp_ctrl_hdr->command_code = cmd_code;
}

encode_decode_rc
mctp_encode_resolve_eid_resp(struct mctp_msg *response, size_t *length,
			     uint8_t rq_dgram_inst, uint8_t completion_code,
			     uint8_t bridge_eid, struct variable_field *address)
{
	if (response == NULL || address == NULL || address->data == NULL ||
	    length == NULL)
		return INPUT_ERROR;
	if ((*length) !=
	    sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) + address->data_size)
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	struct mctp_ctrl_cmd_resolve_eid_resp *resp =
		(struct mctp_ctrl_cmd_resolve_eid_resp *)(response);
	resp->completion_code = completion_code;
	if (completion_code != MCTP_CTRL_CC_SUCCESS) {
		*length = sizeof(struct mctp_ctrl_msg_hdr) + sizeof(uint8_t);
		return SUCCESS;
	}
	resp->bridge_eid = bridge_eid;
	memcpy(resp->physical_address, address->data, address->data_size);
	return SUCCESS;
}

encode_decode_rc mctp_encode_allocate_endpoint_id_resp(
	struct mctp_msg *response, size_t *length, uint8_t rq_dgram_inst,
	mctp_ctrl_cmd_allocate_eids_resp_op op, uint8_t completion_code,
	uint8_t eid_pool_size, uint8_t first_eid)
{
	if (response == NULL || length == NULL)
		return INPUT_ERROR;
	if (*length != sizeof(struct mctp_ctrl_cmd_allocate_eids_resp))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	struct mctp_ctrl_cmd_allocate_eids_resp *resp =
		(struct mctp_ctrl_cmd_allocate_eids_resp *)(response);
	resp->completion_code = completion_code;
	if (completion_code != MCTP_CTRL_CC_SUCCESS) {
		*length = sizeof(struct mctp_ctrl_msg_hdr) + sizeof(uint8_t);
		return SUCCESS;
	}
	resp->operation = op;
	resp->eid_pool_size = eid_pool_size;
	resp->first_eid = first_eid;
	return SUCCESS;
}

encode_decode_rc mctp_encode_set_eid_resp(struct mctp_msg *response,
					  size_t *length, uint8_t rq_dgram_inst,
					  uint8_t completion_code,
					  uint8_t eid_pool_size, uint8_t status,
					  mctp_eid_t eid_set)
{
	if (response == NULL || length == NULL)
		return INPUT_ERROR;
	if (*length != sizeof(struct mctp_ctrl_resp_set_eid))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	struct mctp_ctrl_resp_set_eid *resp =
		(struct mctp_ctrl_resp_set_eid *)(response);
	resp->completion_code = completion_code;
	if (completion_code != MCTP_CTRL_CC_SUCCESS) {
		*length = sizeof(struct mctp_ctrl_msg_hdr) + sizeof(uint8_t);
		return SUCCESS;
	}
	resp->eid_pool_size = eid_pool_size;
	resp->status = status;
	resp->eid_set = eid_set;
	return SUCCESS;
}

encode_decode_rc mctp_encode_get_uuid_resp(struct mctp_msg *response,
					   size_t *length,
					   uint8_t rq_dgram_inst,
					   uint8_t completion_code,
					   const guid_t *uuid)
{
	if (response == NULL || uuid == NULL || length == NULL)
		return INPUT_ERROR;
	if (*length != sizeof(struct mctp_ctrl_resp_get_uuid))
		return GENERIC_ERROR;

	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	struct mctp_ctrl_resp_get_uuid *resp =
		(struct mctp_ctrl_resp_get_uuid *)(response);

	resp->completion_code = completion_code;
	if (completion_code != MCTP_CTRL_CC_SUCCESS) {
		*length = sizeof(struct mctp_ctrl_msg_hdr) + sizeof(uint8_t);
		return SUCCESS;
	}
	resp->uuid = *uuid;
	return SUCCESS;
}

encode_decode_rc mctp_encode_get_networkid_resp(struct mctp_msg *response,
						size_t *length,
						uint8_t completion_code,
						guid_t *network_id)
{
	if (response == NULL || network_id == NULL || length == NULL)
		return INPUT_ERROR;
	if (*length < sizeof(struct mctp_ctrl_get_networkid_resp))
		return GENERIC_ERROR;
	struct mctp_ctrl_get_networkid_resp *resp =
		(struct mctp_ctrl_get_networkid_resp *)(response);
	resp->completion_code = completion_code;
	if (completion_code != MCTP_CTRL_CC_SUCCESS) {
		*length = sizeof(struct mctp_ctrl_msg_hdr) + sizeof(uint8_t);
		return SUCCESS;
	}
	resp->networkid = *network_id;
	return SUCCESS;
}

encode_decode_rc mctp_encode_get_routing_table_resp(
	struct mctp_msg *response, size_t *length, uint8_t completion_code,
	struct get_routing_table_entry_with_address *entries,
	uint8_t no_of_entries, const uint8_t next_entry_handle,
	size_t *resp_size)
{
	uint8_t *cur_entry;
	uint8_t entry_num;

	if (response == NULL || entries == NULL || resp_size == NULL ||
	    length == NULL)
		return INPUT_ERROR;

	if (*length < sizeof(struct mctp_ctrl_resp_get_routing_table))
		return GENERIC_ERROR;
	struct mctp_ctrl_resp_get_routing_table *resp =
		(struct mctp_ctrl_resp_get_routing_table *)(response);

	resp->completion_code = completion_code;
	if (completion_code != MCTP_CTRL_CC_SUCCESS) {
		*length = sizeof(struct mctp_ctrl_msg_hdr) + sizeof(uint8_t);
		return SUCCESS;
	}

	resp->next_entry_handle = next_entry_handle;
	resp->number_of_entries = no_of_entries;
	cur_entry = (uint8_t *)resp->entries;
	for (entry_num = 0; entry_num < no_of_entries; entry_num++) {
		size_t current_entry_size =
			sizeof(struct get_routing_table_entry_with_address) +
			entries[entry_num].routing_info.phys_address_size -
			MAX_PHYSICAL_ADDRESS_SIZE;
		memcpy(cur_entry, entries + entry_num, current_entry_size);
		cur_entry += current_entry_size;
	}
	*resp_size = (size_t)(cur_entry - (uint8_t *)(resp));
	return SUCCESS;
}

encode_decode_rc mctp_encode_get_ver_support_resp(struct mctp_msg *response,
						  size_t *length,
						  uint8_t rq_dgram_inst,
						  uint8_t completion_code,
						  uint8_t number_of_entries,
						  struct version_entry *vers)
{
	if (response == NULL || vers == NULL || length == NULL)
		return INPUT_ERROR;
	if (*length < sizeof(struct mctp_ctrl_resp_get_mctp_ver_support))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);
	struct mctp_ctrl_resp_get_mctp_ver_support *resp =
		(struct mctp_ctrl_resp_get_mctp_ver_support *)(response);
	resp->completion_code = completion_code;
	if (completion_code != MCTP_CTRL_CC_SUCCESS) {
		*length = sizeof(struct mctp_ctrl_msg_hdr) + sizeof(uint8_t);
		return SUCCESS;
	}
	resp->number_of_entries = number_of_entries;
	resp->version = vers[0];
	for (int i = 0; i < number_of_entries - 1; i++) {
		resp->versions[i] = vers[i + 1];
	}
	return SUCCESS;
}

encode_decode_rc mctp_encode_get_eid_resp(struct mctp_msg *response,
					  size_t *length, uint8_t rq_dgram_inst,
					  uint8_t completion_code,
					  mctp_eid_t eid, uint8_t eid_type,
					  uint8_t medium_data)
{
	if (response == NULL || length == NULL)
		return INPUT_ERROR;
	if (*length < sizeof(struct mctp_ctrl_resp_get_eid))
		return GENERIC_ERROR;
	encode_ctrl_cmd_header(&response->msg_hdr, rq_dgram_inst,
			       MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	struct mctp_ctrl_resp_get_eid *resp =
		(struct mctp_ctrl_resp_get_eid *)(response);
	resp->completion_code = completion_code;
	if (completion_code != MCTP_CTRL_CC_SUCCESS) {
		*length = sizeof(struct mctp_ctrl_msg_hdr) + sizeof(uint8_t);
		return SUCCESS;
	}
	resp->eid = eid;
	resp->eid_type = eid_type;
	resp->medium_data = medium_data;
	return SUCCESS;
}
