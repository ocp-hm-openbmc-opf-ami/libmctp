#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-decode-response.h"
#include "test_sample_ids.h"

static void test_decode_resolve_eid_resp()
{
	encode_decode_rc ret;
	uint8_t packed_packet[] = {
		0,
		1,
		(uint8_t)MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID,
		(uint8_t)MCTP_CTRL_CC_SUCCESS,
		10, // Bridge EID
		12 // Physical address
	};
	struct mctp_ctrl_cmd_resolve_eid_resp *response =
		(struct mctp_ctrl_cmd_resolve_eid_resp *)packed_packet;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct variable_field address;
	uint8_t completion_code;
	uint8_t bridge_eid;
	struct mctp_msg *resp = (struct mctp_msg *)(response);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code,
					   &bridge_eid, &address);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code == response->ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == response->ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == response->ctrl_msg_hdr.ic_msg_type);
	assert(!memcmp(address.data,
		       (uint8_t *)response +
			       sizeof(struct mctp_ctrl_cmd_resolve_eid_resp),
		       address.data_size));

	assert(completion_code == response->completion_code);
	assert(bridge_eid == response->bridge_eid);
	assert(address.data_size ==
	       sizeof(packed_packet) -
		       sizeof(struct mctp_ctrl_cmd_resolve_eid_resp));
}

static void test_negative_decode_resolve_eid_resp()
{
	encode_decode_rc ret;
	uint8_t packed_packet[] = {
		0,
		1,
		(uint8_t)MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID,
		(uint8_t)MCTP_CTRL_CC_SUCCESS,
		10, // Bridge EID
		12 // Phsyical address
	};
	struct mctp_ctrl_cmd_resolve_eid_resp *response =
		(struct mctp_ctrl_cmd_resolve_eid_resp *)packed_packet;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct variable_field address;
	uint8_t bridge_eid;
	uint8_t completion_code;
	struct mctp_msg *resp = (struct mctp_msg *)(response);
	response->completion_code = MCTP_CTRL_CC_SUCCESS;
	response->ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;

	ret = mctp_decode_resolve_eid_resp(NULL, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code,
					   &bridge_eid, &address);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, 0, &ctrl_hdr, &completion_code,
					   &bridge_eid, &address);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet), NULL,
					   &completion_code, &bridge_eid,
					   &address);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, NULL, &bridge_eid,
					   &address);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code, NULL,
					   &address);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code,
					   &bridge_eid, NULL);
	assert(ret == INPUT_ERROR);
	response->completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code,
					   &bridge_eid, &address);
	assert(ret == CC_ERROR);
	response->ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code,
					   &bridge_eid, &address);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_allocate_eid_pool_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_allocate_eids_resp response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.operation = allocation_accepted;
	response.eid_pool_size = 10;
	response.first_eid = 9;
	uint8_t completion_code;
	mctp_ctrl_cmd_allocate_eids_resp_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &completion_code, &op, &eid_pool_size, &first_eid);

	assert(ret == SUCCESS);
	assert(ctrl_hdr.ic_msg_type == response.ctrl_hdr.ic_msg_type);
	assert(ctrl_hdr.rq_dgram_inst == response.ctrl_hdr.rq_dgram_inst);
	assert(ctrl_hdr.command_code == response.ctrl_hdr.command_code);
	assert(completion_code == response.completion_code);
	assert(op == response.operation);
	assert(eid_pool_size == response.eid_pool_size);
	assert(first_eid == response.first_eid);
}

static void test_negative_decode_allocate_eid_pool_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_allocate_eids_resp response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.operation = allocation_accepted;
	response.eid_pool_size = 10;
	response.first_eid = 9;
	uint8_t completion_code;
	mctp_ctrl_cmd_allocate_eids_resp_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_allocate_endpoint_id_resp(
		NULL, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &completion_code, &op, &eid_pool_size, &first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp), NULL,
		&completion_code, &op, &eid_pool_size, &first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, NULL, &op, &eid_pool_size, &first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &completion_code, NULL, &eid_pool_size, &first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &completion_code, &op, NULL, &first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &completion_code, &op, &eid_pool_size, NULL);
	assert(ret == INPUT_ERROR);

	ret = mctp_decode_allocate_endpoint_id_resp(resp, 0, &ctrl_hdr,
						    &completion_code, &op,
						    &eid_pool_size, &first_eid);
	assert(ret == GENERIC_ERROR);

	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &completion_code, &op, &eid_pool_size, &first_eid);
	assert(ret == CC_ERROR);

	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &completion_code, &op, &eid_pool_size, &first_eid);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_set_eid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_resp_set_eid response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
	response.eid_pool_size = 9;
	response.eid_set = 12;
	response.status = 8;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	uint8_t eid_pool_size;
	uint8_t eid_set;
	uint8_t status;
	uint8_t completion_code;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, &eid_set);
	assert(ret == SUCCESS);

	assert(ctrl_hdr.command_code == response.ctrl_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == response.ctrl_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == response.ctrl_hdr.ic_msg_type);
	assert(response.completion_code == completion_code);
	assert(response.status == status);
	assert(response.eid_pool_size == eid_pool_size);
	assert(response.eid_set == eid_set);
}

static void test_negative_decode_set_eid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_resp_set_eid response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
	response.eid_pool_size = 9;
	response.eid_set = 12;
	response.status = 8;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	uint8_t eid_pool_size;
	uint8_t eid_set;
	uint8_t status;
	uint8_t completion_code;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_set_eid_resp(NULL,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, &eid_set);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       NULL, &completion_code, &eid_pool_size,
				       &status, &eid_set);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, NULL, &eid_pool_size, &status,
				       &eid_set);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code, NULL,
				       &status, &eid_set);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, NULL, &eid_set);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, NULL);
	assert(ret == INPUT_ERROR);

	ret = mctp_decode_set_eid_resp(resp, 0, &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, &eid_set);
	assert(ret == GENERIC_ERROR);

	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, &eid_set);
	assert(ret == CC_ERROR);

	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, &eid_set);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_uuid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_resp_get_uuid response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	guid_t uuid;

	response.uuid.canonical.data1 = 10;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;
	uint8_t completion_code;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, &completion_code, &uuid);
	assert(ret == SUCCESS);

	assert(memcmp(&response.ctrl_hdr, &ctrl_hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
	assert(completion_code == response.completion_code);
	assert(uuid.canonical.data1 == response.uuid.canonical.data1);
	assert(memcmp(&response.uuid, &uuid, sizeof(guid_t)) == 0);
}

static void test_negative_decode_get_uuid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct mctp_ctrl_resp_get_uuid response;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	guid_t uuid;

	response.uuid.canonical.data1 = 10;
	response.completion_code = MCTP_CTRL_CC_ERROR;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;
	uint8_t completion_code;
	ret = mctp_decode_get_uuid_resp(NULL,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, &completion_code, &uuid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_uuid_resp(resp, 0, &ctrl_hdr, &completion_code,
					&uuid);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					NULL, &completion_code, &uuid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, NULL, &uuid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, &completion_code, NULL);
	assert(ret == INPUT_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, &completion_code, &uuid);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_networkid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_get_networkid_resp response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	guid_t network_id;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;

	response.networkid.canonical.data1 = 10;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_NETWORK_ID;
	uint8_t completion_code;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		&completion_code, &network_id);
	assert(ret == SUCCESS);

	assert(memcmp(&response.ctrl_hdr, &ctrl_hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
	assert(completion_code == response.completion_code);
	assert(network_id.canonical.data1 ==
	       response.networkid.canonical.data1);
	assert(memcmp(&response.networkid, &network_id, sizeof(guid_t)) == 0);
}

static void test_negative_decode_get_networkid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct mctp_ctrl_get_networkid_resp response;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	guid_t network_id;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;

	response.networkid.canonical.data1 = 10;
	response.completion_code = MCTP_CTRL_CC_ERROR;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_NETWORK_ID;
	uint8_t completion_code;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;

	ret = mctp_decode_get_networkid_resp(
		NULL, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		&completion_code, &network_id);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_networkid_resp(resp, 0, &ctrl_hdr,
					     &completion_code, &network_id);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), NULL,
		&completion_code, &network_id);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		NULL, &network_id);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		&completion_code, NULL);
	assert(ret == INPUT_ERROR);
	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		&completion_code, &network_id);
	assert(ret == CC_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		&completion_code, &network_id);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_ver_support_resp()
{
	encode_decode_rc ret;
	uint8_t number_of_entries;
	uint8_t completion_code;
	uint8_t expected_instance_id = 0x01;
	uint8_t response_buffer
		[13]; // sizeof(mctp_get_ver_support_resp) + sizeof(single_version)
	struct mctp_ctrl_resp_get_mctp_ver_support *response =
		(struct mctp_ctrl_resp_get_mctp_ver_support *)(response_buffer);
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct version_entry vers[2];
	size_t verslen;
	response->version.major = 2;
	response->version.minor = 3;
	response->version.update = 4;
	response->version.alpha = 5;
	response->versions[0].major = 1;
	response->versions[0].minor = 243;
	response->versions[0].update = 240;
	response->versions[0].alpha = 244;
	response->ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response->ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response->ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_VERSION_SUPPORT;
	response->number_of_entries = 2;
	response->completion_code = MCTP_CTRL_CC_SUCCESS;
	verslen = response->number_of_entries;
	struct mctp_msg *resp = (struct mctp_msg *)(response);

	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, &number_of_entries, vers, verslen);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code == response->ctrl_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == response->ctrl_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == response->ctrl_hdr.ic_msg_type);
	assert(number_of_entries == response->number_of_entries);
	assert(vers[0].major == response->version.major);
	assert(vers[0].minor == response->version.minor);
	assert(vers[0].update == response->version.update);
	assert(vers[0].alpha == response->version.alpha);
	for (int i = 0; i < number_of_entries - 1; i++) {
		assert(vers[i + 1].major == response->versions[i].major);
		assert(vers[i + 1].minor == response->versions[i].minor);
		assert(vers[i + 1].update == response->versions[i].update);
		assert(vers[i + 1].alpha == response->versions[i].alpha);
	}
}

static void test_negative_decode_get_ver_support_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_resp_get_mctp_ver_support response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t number_of_entries;
	uint8_t completion_code;
	struct version_entry vers;
	size_t verslen = 2;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_VERSION_SUPPORT;
	response.version.major = 2;
	response.version.minor = 3;
	response.version.update = 4;
	response.version.alpha = 5;

	ret = mctp_decode_get_ver_support_resp(
		NULL, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, &number_of_entries, &vers,
		verslen);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_ver_support_resp(resp, 0, &ctrl_hdr,
					       &completion_code,
					       &number_of_entries, &vers,
					       verslen);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support), NULL,
		&completion_code, &number_of_entries, &vers, verslen);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, NULL, &number_of_entries, &vers, verslen);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, NULL, &vers, verslen);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, &number_of_entries, NULL, verslen);
	assert(ret == INPUT_ERROR);

	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, &number_of_entries, &vers,
		verslen);
	assert(ret == CC_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, &number_of_entries, &vers,
		verslen);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_eid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_resp_get_eid response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID;
	response.eid = 12;
	response.eid_type = 1;
	response.medium_data = 8;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	uint8_t eid;
	uint8_t eid_type;
	uint8_t medium_data;
	uint8_t completion_code;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid,
				       &eid_type, &medium_data);
	assert(ret == SUCCESS);

	assert(ctrl_hdr.command_code == response.ctrl_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == response.ctrl_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == response.ctrl_hdr.ic_msg_type);
	assert(response.completion_code == completion_code);
	assert(response.eid == eid);
	assert(response.eid_type == eid_type);
	assert(response.medium_data == medium_data);
}

static void test_negative_decode_get_eid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct mctp_ctrl_resp_get_eid response;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	uint8_t eid;
	uint8_t eid_type;
	uint8_t medium_data;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;

	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID;
	response.eid = 12;
	response.eid_type = 1;
	response.medium_data = 8;

	uint8_t completion_code;
	ret = mctp_decode_get_eid_resp(NULL,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid,
				       &eid_type, &medium_data);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       NULL, &completion_code, &eid, &eid_type,
				       &medium_data);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, NULL, &eid, &eid_type,
				       &medium_data);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, NULL,
				       &eid_type, &medium_data);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid, NULL,
				       &medium_data);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid,
				       &eid_type, NULL);
	assert(ret == INPUT_ERROR);

	ret = mctp_decode_get_eid_resp(resp, 0, &ctrl_hdr, &completion_code,
				       &eid, &eid_type, &medium_data);
	assert(ret == GENERIC_ERROR);
	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid,
				       &eid_type, &medium_data);
	assert(ret == CC_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid,
				       &eid_type, &medium_data);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_vdm_support_pcie_resp()
{
	encode_decode_rc ret;
	const uint8_t sample[] = {
		0, 200, 6, 0, 0xFF, 0, 0x80, 0x86, 0x12, 0x34
	};
	struct mctp_ctrl_resp_get_vdm_support *response =
		(struct mctp_ctrl_resp_get_vdm_support *)sample;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t vendor_id_set_selector;
	uint8_t vendor_id_format;
	struct variable_field vendor_id_data;
	uint16_t cmd_set_type;
	const uint8_t rq_d_inst = 200;

	struct mctp_msg *resp = (struct mctp_msg *)(response);

	ret = mctp_decode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		&completion_code, &vendor_id_set_selector, &vendor_id_format,
		&vendor_id_data, &cmd_set_type);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT);
	assert(ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(vendor_id_set_selector == 0xFF);
	assert(vendor_id_format == MCTP_GET_VDM_SUPPORT_PCIE_FORMAT_ID);
	assert(memcmp((sample + 6), vendor_id_data.data, sizeof(uint16_t)) ==
	       0);
	assert(vendor_id_data.data_size == sizeof(uint16_t));
	assert(cmd_set_type == 0x1234);
}

static void test_decode_get_vdm_support_iana_resp()
{
	encode_decode_rc ret;
	const uint8_t sample[] = { 0,	 200,  6,    0,	   0xFF, 1,
				   0x12, 0x34, 0x56, 0x78, 0x12, 0x34 };
	struct mctp_ctrl_resp_get_vdm_support *response =
		(struct mctp_ctrl_resp_get_vdm_support *)sample;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t vendor_id_set_selector;
	uint8_t vendor_id_format;
	struct variable_field vendor_id_data;
	uint16_t cmd_set_type;
	const uint8_t rq_d_inst = 200;

	struct mctp_msg *resp = (struct mctp_msg *)(response);

	ret = mctp_decode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		&completion_code, &vendor_id_set_selector, &vendor_id_format,
		&vendor_id_data, &cmd_set_type);
	assert(ret == SUCCESS);
	assert(response->ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT);
	assert(response->ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response->ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response->vendor_id_set_selector == vendor_id_set_selector);
	assert(response->vendor_id_format == vendor_id_format);
	assert(memcmp(&response->vendor_id_data_iana, vendor_id_data.data,
		      sizeof(uint32_t)) == 0);
	assert(vendor_id_data.data_size == sizeof(uint32_t));
	assert(be16toh(response->cmd_set_type) == cmd_set_type);
}

static void test_negative_decode_get_vdm_support_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_resp_get_vdm_support response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	uint8_t vendor_id_set_selector;
	uint8_t vendor_id_format;
	struct variable_field vendor_id_data;
	uint16_t cmd_set_type;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.ctrl_hdr.command_code =
		MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT;

	ret = mctp_decode_get_vdm_support_resp(
		NULL, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		&completion_code, &vendor_id_set_selector, &vendor_id_format,
		&vendor_id_data, &cmd_set_type);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_vdm_support_resp(
		resp, 0, &ctrl_hdr, &completion_code, &vendor_id_set_selector,
		&vendor_id_format, &vendor_id_data, &cmd_set_type);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), NULL,
		&completion_code, &vendor_id_set_selector, &vendor_id_format,
		&vendor_id_data, &cmd_set_type);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		NULL, &vendor_id_set_selector, &vendor_id_format,
		&vendor_id_data, &cmd_set_type);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		&completion_code, NULL, &vendor_id_format, &vendor_id_data,
		&cmd_set_type);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		&completion_code, &vendor_id_set_selector, NULL,
		&vendor_id_data, &cmd_set_type);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_vdm_support_resp(
		NULL, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		&completion_code, &vendor_id_set_selector, &vendor_id_format,
		NULL, &cmd_set_type);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		&completion_code, &vendor_id_set_selector, &vendor_id_format,
		&vendor_id_data, NULL);
	assert(ret == INPUT_ERROR);
	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		&completion_code, &vendor_id_set_selector, &vendor_id_format,
		&vendor_id_data, &cmd_set_type);
	assert(ret == CC_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), &ctrl_hdr,
		&completion_code, &vendor_id_set_selector, &vendor_id_format,
		&vendor_id_data, &cmd_set_type);
	assert(ret == GENERIC_ERROR);
}

int main(int argc, char *argv[])
{
	test_decode_resolve_eid_resp();
	test_decode_allocate_eid_pool_resp();
	test_decode_set_eid_resp();
	test_decode_get_uuid_resp();
	test_decode_get_networkid_resp();
	test_decode_get_ver_support_resp();
	test_decode_get_eid_resp();
	test_decode_get_vdm_support_pcie_resp();
	test_decode_get_vdm_support_iana_resp();

	/*Negative test cases */
	test_negative_decode_resolve_eid_resp();
	test_negative_decode_allocate_eid_pool_resp();
	test_negative_decode_set_eid_resp();
	test_negative_decode_get_uuid_resp();
	test_negative_decode_get_networkid_resp();
	test_negative_decode_get_ver_support_resp();
	test_negative_decode_get_eid_resp();
	test_negative_decode_get_vdm_support_resp();

	return EXIT_SUCCESS;
}
