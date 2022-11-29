#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-decode-response.h"

static void test_decode_resolve_eid_resp()
{
	decode_rc ret;
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
	uint8_t completion_code;
	uint8_t bridge_eid;
	struct mctp_msg *resp = (struct mctp_msg *)(response);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code,
					   &bridge_eid, &address);
	assert(ret == DECODE_SUCCESS);
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
	decode_rc ret;
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
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, 0, &ctrl_hdr, &completion_code,
					   &bridge_eid, &address);
	assert(ret == DECODE_GENERIC_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet), NULL,
					   &completion_code, &bridge_eid,
					   &address);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, NULL, &bridge_eid,
					   &address);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code, NULL,
					   &address);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code,
					   &bridge_eid, NULL);
	assert(ret == DECODE_INPUT_ERROR);
	response->completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code,
					   &bridge_eid, &address);
	assert(ret == DECODE_CC_ERROR);
	response->ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_resolve_eid_resp(resp, sizeof(packed_packet),
					   &ctrl_hdr, &completion_code,
					   &bridge_eid, &address);
	assert(ret == DECODE_GENERIC_ERROR);
}

static void test_decode_allocate_eid_pool_resp()
{
	decode_rc ret;
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
	uint8_t cc;
	mctp_ctrl_cmd_allocate_eids_resp_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &cc, &op, &eid_pool_size, &first_eid);

	assert(ret == DECODE_SUCCESS);
	assert(ctrl_hdr.ic_msg_type == response.ctrl_hdr.ic_msg_type);
	assert(ctrl_hdr.rq_dgram_inst == response.ctrl_hdr.rq_dgram_inst);
	assert(ctrl_hdr.command_code == response.ctrl_hdr.command_code);
	assert(cc == response.completion_code);
	assert(op == response.operation);
	assert(eid_pool_size == response.eid_pool_size);
	assert(first_eid == response.first_eid);
}

static void test_negative_decode_allocate_eid_pool_resp()
{
	decode_rc ret;
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
	uint8_t cc;
	mctp_ctrl_cmd_allocate_eids_resp_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_allocate_endpoint_id_resp(
		NULL, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &cc, &op, &eid_pool_size, &first_eid);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp), NULL,
		&cc, &op, &eid_pool_size, &first_eid);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, NULL, &op, &eid_pool_size, &first_eid);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &cc, NULL, &eid_pool_size, &first_eid);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &cc, &op, NULL, &first_eid);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &cc, &op, &eid_pool_size, NULL);
	assert(ret == DECODE_INPUT_ERROR);

	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, 0, &ctrl_hdr, &cc, &op, &eid_pool_size, &first_eid);
	assert(ret == DECODE_GENERIC_ERROR);

	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &cc, &op, &eid_pool_size, &first_eid);
	assert(ret == DECODE_CC_ERROR);

	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, &cc, &op, &eid_pool_size, &first_eid);
	assert(ret == DECODE_GENERIC_ERROR);
}

static void test_decode_set_eid_resp()
{
	decode_rc ret;
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
	assert(ret == DECODE_SUCCESS);

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
	decode_rc ret;
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
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       NULL, &completion_code, &eid_pool_size,
				       &status, &eid_set);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, NULL, &eid_pool_size, &status,
				       &eid_set);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code, NULL,
				       &status, &eid_set);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, NULL, &eid_set);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, NULL);
	assert(ret == DECODE_INPUT_ERROR);

	ret = mctp_decode_set_eid_resp(resp, 0, &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, &eid_set);
	assert(ret == DECODE_GENERIC_ERROR);

	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, &eid_set);
	assert(ret == DECODE_CC_ERROR);

	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, &completion_code,
				       &eid_pool_size, &status, &eid_set);
	assert(ret == DECODE_GENERIC_ERROR);
}

static void test_decode_get_uuid_resp()
{
	decode_rc ret;
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
	assert(ret == DECODE_SUCCESS);

	assert(memcmp(&response.ctrl_hdr, &ctrl_hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
	assert(completion_code == response.completion_code);
	assert(uuid.canonical.data1 == response.uuid.canonical.data1);
	assert(memcmp(&response.uuid, &uuid, sizeof(guid_t)) == 0);
}

static void test_negative_decode_get_uuid_resp()
{
	decode_rc ret;
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
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_uuid_resp(resp, 0, &ctrl_hdr, &completion_code,
					&uuid);
	assert(ret == DECODE_GENERIC_ERROR);
	ret = mctp_decode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					NULL, &completion_code, &uuid);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, NULL, &uuid);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, &completion_code, NULL);
	assert(ret == DECODE_INPUT_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, &completion_code, &uuid);
	assert(ret == DECODE_GENERIC_ERROR);
}

static void test_decode_get_networkid_resp()
{
	decode_rc ret;
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
	assert(ret == DECODE_SUCCESS);

	assert(memcmp(&response.ctrl_hdr, &ctrl_hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
	assert(completion_code == response.completion_code);
	assert(network_id.canonical.data1 ==
	       response.networkid.canonical.data1);
	assert(memcmp(&response.networkid, &network_id, sizeof(guid_t)) == 0);
}

static void test_negative_decode_get_networkid_resp()
{
	decode_rc ret;
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
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_networkid_resp(resp, 0, &ctrl_hdr,
					     &completion_code, &network_id);
	assert(ret == DECODE_GENERIC_ERROR);
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), NULL,
		&completion_code, &network_id);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		NULL, &network_id);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		&completion_code, NULL);
	assert(ret == DECODE_INPUT_ERROR);
	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		&completion_code, &network_id);
	assert(ret == DECODE_CC_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &ctrl_hdr,
		&completion_code, &network_id);
	assert(ret == DECODE_GENERIC_ERROR);
}

static void test_decode_get_ver_support_resp()
{
	decode_rc ret;
	uint8_t number_of_entries;
	uint8_t completion_code;
	uint8_t expected_instance_id = 0x01;
	struct mctp_ctrl_resp_get_mctp_ver_support response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_VERSION_SUPPORT;
	response.number_of_entries = 9;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;

	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, &number_of_entries);
	assert(ret == DECODE_SUCCESS);
	assert(ctrl_hdr.command_code == response.ctrl_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == response.ctrl_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == response.ctrl_hdr.ic_msg_type);
	assert(number_of_entries == response.number_of_entries);
}

static void test_negative_decode_get_ver_support_resp()
{
	decode_rc ret;
	struct mctp_ctrl_resp_get_mctp_ver_support response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t number_of_entries;
	uint8_t completion_code;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_VERSION_SUPPORT;

	ret = mctp_decode_get_ver_support_resp(
		NULL, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, &number_of_entries);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_ver_support_resp(
		resp, 0, &ctrl_hdr, &completion_code, &number_of_entries);
	assert(ret == DECODE_GENERIC_ERROR);
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support), NULL,
		&completion_code, &number_of_entries);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, NULL, &number_of_entries);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, NULL);
	assert(ret == DECODE_INPUT_ERROR);
	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, &number_of_entries);
	assert(ret == DECODE_CC_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		&ctrl_hdr, &completion_code, &number_of_entries);
	assert(ret == DECODE_GENERIC_ERROR);
}

static void test_decode_get_eid_resp()
{
	decode_rc ret;
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
	assert(ret == DECODE_SUCCESS);

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
	decode_rc ret;
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
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       NULL, &completion_code, &eid, &eid_type,
				       &medium_data);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, NULL, &eid, &eid_type,
				       &medium_data);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, NULL,
				       &eid_type, &medium_data);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid, NULL,
				       &medium_data);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid,
				       &eid_type, NULL);
	assert(ret == DECODE_INPUT_ERROR);

	ret = mctp_decode_get_eid_resp(resp, 0, &ctrl_hdr, &completion_code,
				       &eid, &eid_type, &medium_data);
	assert(ret == DECODE_GENERIC_ERROR);
	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid,
				       &eid_type, &medium_data);
	assert(ret == DECODE_CC_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       &ctrl_hdr, &completion_code, &eid,
				       &eid_type, &medium_data);
	assert(ret == DECODE_GENERIC_ERROR);
}

static void test_decode_prepare_discovery_resp()
{
	decode_rc ret;
	uint8_t expected_instance_id = 0x01;
	struct mctp_ctrl_resp_prepare_discovery response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code =
		MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_prepare_discovery_resp(
		resp, sizeof(struct mctp_ctrl_resp_prepare_discovery),
		&ctrl_hdr, &completion_code);
	assert(ret == DECODE_SUCCESS);
	assert(ctrl_hdr.command_code == response.ctrl_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == response.ctrl_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == response.ctrl_hdr.ic_msg_type);
}

static void test_negative_decode_prepare_discovery_resp()
{
	decode_rc ret;
	uint8_t expected_instance_id = 0x01;
	struct mctp_ctrl_resp_prepare_discovery response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t completion_code;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code =
		MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.ctrl_hdr.command_code =
		MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY;

	ret = mctp_decode_prepare_discovery_resp(
		NULL, sizeof(struct mctp_ctrl_resp_prepare_discovery),
		&ctrl_hdr, &completion_code);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_prepare_discovery_resp(resp, 0, &ctrl_hdr,
						 &completion_code);
	assert(ret == DECODE_GENERIC_ERROR);
	ret = mctp_decode_prepare_discovery_resp(
		resp, sizeof(struct mctp_ctrl_resp_prepare_discovery), NULL,
		&completion_code);
	assert(ret == DECODE_INPUT_ERROR);
	ret = mctp_decode_prepare_discovery_resp(
		resp, sizeof(struct mctp_ctrl_resp_prepare_discovery),
		&ctrl_hdr, NULL);
	assert(ret == DECODE_INPUT_ERROR);
	response.completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_prepare_discovery_resp(
		resp, sizeof(struct mctp_ctrl_resp_prepare_discovery),
		&ctrl_hdr, &completion_code);
	assert(ret == DECODE_CC_ERROR);
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_prepare_discovery_resp(
		resp, sizeof(struct mctp_ctrl_resp_prepare_discovery),
		&ctrl_hdr, &completion_code);
	assert(ret == DECODE_GENERIC_ERROR);
}
int main(int argc, char *argv[])
{
	test_decode_resolve_eid_resp();
	test_decode_allocate_eid_pool_resp();
	test_decode_set_eid_resp();
	test_decode_get_networkid_resp();
	test_decode_get_uuid_resp();
	test_decode_get_ver_support_resp();
	test_decode_get_eid_resp();
	test_decode_prepare_discovery_resp();

	/*Negative test cases */
	test_negative_decode_resolve_eid_resp();
	test_negative_decode_allocate_eid_pool_resp();
	test_negative_decode_set_eid_resp();
	test_negative_decode_get_networkid_resp();
	test_negative_decode_get_uuid_resp();
	test_negative_decode_get_ver_support_resp();
	test_negative_decode_get_eid_resp();
	test_negative_decode_prepare_discovery_resp();

	return EXIT_SUCCESS;
}