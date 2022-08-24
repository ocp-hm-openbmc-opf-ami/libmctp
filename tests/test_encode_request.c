#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-encode-request.h"

static void test_encode_resolve_eid_req()
{
	encode_decode_api_return_code ret;
	const uint8_t target_eid = 9;
	const uint8_t instance_id = 0x01;
	struct mctp_ctrl_cmd_resolve_eid_req cmd_resolve_eid;

	ret = mctp_encode_resolve_eid_req(
		&cmd_resolve_eid, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		target_eid);
	assert(ret == ENCODE_SUCCESS);
	assert(cmd_resolve_eid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	assert(cmd_resolve_eid.ctrl_msg_hdr.rq_dgram_inst ==
	       (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(cmd_resolve_eid.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);

	assert(cmd_resolve_eid.target_eid == target_eid);
}

static void test_negative_encode_resolve_eid_req()
{
	encode_decode_api_return_code ret;
	struct mctp_ctrl_cmd_resolve_eid_req *cmd_resolve_eid = NULL;
	const uint8_t target_eid = 9;
	const uint8_t instance_id = 0x01;

	ret = mctp_encode_resolve_eid_req(
		cmd_resolve_eid, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		target_eid);

	assert(ret == INPUT_ERROR);
}

static void test_encode_allocate_eid_pool_req()
{
	encode_decode_api_return_code ret;
	const uint8_t first_eid = 9;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_req_op operation = allocate_eids;
	struct mctp_ctrl_cmd_allocate_eids_req cmd_allocate_eid;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;

	ret = mctp_encode_allocate_endpoint_id_req(&cmd_allocate_eid, rq_d_inst,
						   operation, eid_pool_size,
						   first_eid);
	assert(ret == ENCODE_SUCCESS);
	assert(cmd_allocate_eid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	assert(cmd_allocate_eid.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(cmd_allocate_eid.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);

	assert(cmd_allocate_eid.operation == operation);

	assert(cmd_allocate_eid.eid_pool_size == eid_pool_size);
	assert(cmd_allocate_eid.first_eid == first_eid);
}

static void test_negative_encode_allocate_eid_pool_req()
{
	encode_decode_api_return_code ret;
	uint8_t sample_eid = 10;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_req_op operation = allocate_eids;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_ctrl_cmd_allocate_eids_req *cmd_allocate_eid = NULL;

	ret = mctp_encode_allocate_endpoint_id_req(cmd_allocate_eid, rq_d_inst,
						   operation, eid_pool_size,
						   sample_eid);
	assert(ret == INPUT_ERROR);
}

int main(int argc, char *argv[])
{
	test_encode_resolve_eid_req();
	test_encode_allocate_eid_pool_req();

	/*Negative test cases */
	test_negative_encode_resolve_eid_req();
	test_negative_encode_allocate_eid_pool_req();
	return EXIT_SUCCESS;
}