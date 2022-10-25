#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-encode-response.h"

static void test_mctp_encode_resolve_eid_resp()
{
	encode_rc ret;
	uint8_t phy_address[] = { 10, 12, 13 };
	struct mctp_ctrl_cmd_resolve_eid_resp *response;
	struct variable_field address;
	address.data = phy_address;
	address.data_size = sizeof(phy_address);
	response = (struct mctp_ctrl_cmd_resolve_eid_resp *)malloc(
		sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) +
		sizeof(phy_address));
	const uint8_t instance_id = 0x01;
	uint8_t rq_d_inst = instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	const uint8_t bridge_eid = 10;
	struct mctp_msg *resp = (struct mctp_msg *)(response);

	ret = mctp_encode_resolve_eid_resp(
		resp,
		sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) +
			sizeof(phy_address),
		rq_d_inst, bridge_eid, &address);
	assert(ret == ENCODE_SUCCESS);
	assert(response->ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	assert(response->ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(response->ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response->bridge_eid == bridge_eid);
	assert(response->completion_code == MCTP_CTRL_CC_SUCCESS);
	assert(!memcmp(response->physical_address, address.data,
		       address.data_size));
	free(response);
}

static void test_negative_encode_resolve_eid_resp()
{
	encode_rc ret;
	struct mctp_msg response;
	uint8_t phy_address[] = { 10, 12, 13 };
	struct variable_field address;
	address.data = phy_address;
	address.data_size = sizeof(phy_address);
	const uint8_t instance_id = 0x01;
	const uint8_t bridge_eid = 10;
	ret = mctp_encode_resolve_eid_resp(
		NULL,
		sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) +
			sizeof(phy_address),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), bridge_eid,
		&address);
	assert(ret == ENCODE_INPUT_ERROR);
	ret = mctp_encode_resolve_eid_resp(
		&response,
		sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) +
			sizeof(phy_address),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), bridge_eid, NULL);
	assert(ret == ENCODE_INPUT_ERROR);
	ret = mctp_encode_resolve_eid_resp(
		&response, 0, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		bridge_eid, &address);
	assert(ret == ENCODE_GENERIC_ERROR);
	address.data = NULL;
	address.data_size = 0;
	ret = mctp_encode_resolve_eid_resp(
		&response,
		sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) +
			sizeof(phy_address),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), bridge_eid,
		&address);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_allocate_eid_pool_resp()
{
	encode_rc ret;
	struct mctp_ctrl_cmd_allocate_eids_resp response;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	mctp_ctrl_cmd_allocate_eids_resp_op op = allocation_accepted;
	uint8_t eid_pool_size = 10;
	uint8_t first_eid = 9;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		rq_d_inst, op, eid_pool_size, first_eid);
	assert(ret == ENCODE_SUCCESS);

	assert(response.ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response.operation == op);
	assert(response.eid_pool_size == eid_pool_size);
	assert(response.first_eid == first_eid);
}

static void test_negative_encode_allocate_eid_pool_resp()
{
	encode_rc ret;
	struct mctp_msg *response = NULL;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	mctp_ctrl_cmd_allocate_eids_resp_op op = allocation_accepted;
	uint8_t eid_pool_size = 10;
	uint8_t first_eid = 9;

	ret = mctp_encode_allocate_endpoint_id_resp(
		response, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		rq_d_inst, op, eid_pool_size, first_eid);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_allocate_endpoint_id_resp(
		&response1, 0, rq_d_inst, op, eid_pool_size, first_eid);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_set_eid_resp()
{
	encode_rc ret;
	struct mctp_ctrl_resp_set_eid response;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	uint8_t eid_pool_size = 10;
	uint8_t eid_set = 9;
	uint8_t status = 8;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       rq_d_inst, eid_pool_size, status,
				       eid_set);
	assert(ret == ENCODE_SUCCESS);

	assert(response.ctrl_hdr.command_code == MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response.status == status);
	assert(response.eid_pool_size == eid_pool_size);
	assert(response.eid_set == eid_set);
}

static void test_negative_encode_set_eid_resp()
{
	encode_rc ret;
	struct mctp_msg *response = NULL;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	uint8_t eid_pool_size = 9;
	uint8_t eid_set = 10;
	uint8_t status = 8;
	ret = mctp_encode_set_eid_resp(response,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       rq_d_inst, eid_pool_size, status,
				       eid_set);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_set_eid_resp(&response1, 0, rq_d_inst, eid_pool_size,
				       status, eid_set);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_get_uuid_resp()
{
	encode_rc ret;
	struct mctp_ctrl_resp_get_uuid response;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	/* 16 byte UUID */
	char sample_uuid[16] = "61a3";
	guid_t test_uuid;

	/*doing memcpy of string literal*/
	memcpy(&test_uuid.raw, sample_uuid, sizeof(guid_t));
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	ret = mctp_encode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					rq_d_inst, &test_uuid);
	assert(ret == ENCODE_SUCCESS);

	assert(response.ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(memcmp(response.uuid.raw, test_uuid.raw, sizeof(guid_t)) == 0);
}

static void test_negative_encode_get_uuid_resp()
{
	encode_rc ret;
	struct mctp_msg *response = NULL;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	guid_t test_uuid;

	ret = mctp_encode_get_uuid_resp(response,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					rq_d_inst, &test_uuid);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_get_uuid_resp(&response1, 0, rq_d_inst, &test_uuid);
	assert(ret == ENCODE_GENERIC_ERROR);
	ret = mctp_encode_get_uuid_resp(&response1,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					rq_d_inst, NULL);
	assert(ret == ENCODE_INPUT_ERROR);
}

int main(int argc, char *argv[])
{
	test_mctp_encode_resolve_eid_resp();
	test_encode_allocate_eid_pool_resp();
	test_encode_set_eid_resp();
	test_encode_get_uuid_resp();

	/*Negative test cases */
	test_negative_encode_resolve_eid_resp();
	test_negative_encode_allocate_eid_pool_resp();
	test_negative_encode_set_eid_resp();
	test_negative_encode_get_uuid_resp();

	return EXIT_SUCCESS;
}