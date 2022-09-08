#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-encode-response.h"

static void test_mctp_encode_resolve_eid_resp()
{
	encode_decode_api_return_code ret;
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
		resp, sizeof(struct mctp_ctrl_cmd_resolve_eid_resp), rq_d_inst,
		bridge_eid, &address);
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
	encode_decode_api_return_code ret;
	struct mctp_msg response;
	uint8_t phy_address[] = { 10, 12, 13 };
	struct variable_field address;
	address.data = phy_address;
	address.data_size = sizeof(phy_address);
	const uint8_t instance_id = 0x01;
	const uint8_t bridge_eid = 10;
	ret = mctp_encode_resolve_eid_resp(
		NULL, sizeof(struct mctp_ctrl_cmd_resolve_eid_resp),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), bridge_eid,
		&address);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_resolve_eid_resp(
		&response, sizeof(struct mctp_ctrl_cmd_resolve_eid_resp),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), bridge_eid, NULL);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_resolve_eid_resp(
		&response, 0, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		bridge_eid, &address);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_allocate_eid_pool_resp()
{
	encode_decode_api_return_code ret;
	struct mctp_ctrl_cmd_allocate_eids_resp response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	ctrl_hdr.rq_dgram_inst = rq_d_inst;
	ctrl_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;
	mctp_ctrl_cmd_allocate_eids_resp_op op = allocation_accepted;
	uint8_t eid_pool_size = 10;
	uint8_t first_eid = 9;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, op, eid_pool_size, first_eid);
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
	encode_decode_api_return_code ret;
	struct mctp_msg *response = NULL;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	ctrl_hdr.rq_dgram_inst = rq_d_inst;
	ctrl_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;
	mctp_ctrl_cmd_allocate_eids_resp_op op = allocation_accepted;
	uint8_t eid_pool_size = 10;
	uint8_t first_eid = 9;

	ret = mctp_encode_allocate_endpoint_id_resp(
		response, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ctrl_hdr, op, eid_pool_size, first_eid);
	assert(ret == INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_allocate_endpoint_id_resp(
		&response1, 0, &ctrl_hdr, op, eid_pool_size, first_eid);
	assert(ret == GENERIC_ERROR);
}

int main(int argc, char *argv[])
{
	test_mctp_encode_resolve_eid_resp();
	test_encode_allocate_eid_pool_resp();

	/*Negative test cases */
	test_negative_encode_resolve_eid_resp();
	test_negative_encode_allocate_eid_pool_resp();
	return EXIT_SUCCESS;
}