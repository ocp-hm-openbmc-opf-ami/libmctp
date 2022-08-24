#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-decode-request.h"

static void test_decode_resolve_eid_req()
{
	encode_decode_api_return_code ret;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct mctp_ctrl_cmd_resolve_eid_req cmd_resolve_eid;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	cmd_resolve_eid.ctrl_msg_hdr.command_code =
		MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	cmd_resolve_eid.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	cmd_resolve_eid.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t target_eid = 10;
	cmd_resolve_eid.target_eid = 0;

	ret = mctp_decode_resolve_eid_req(&cmd_resolve_eid, &ctrl_hdr,
					  &target_eid);
	assert(ret == DECODE_SUCCESS);
	assert(ctrl_hdr.command_code ==
	       cmd_resolve_eid.ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst ==
	       cmd_resolve_eid.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type ==
	       cmd_resolve_eid.ctrl_msg_hdr.ic_msg_type);
	assert(target_eid == cmd_resolve_eid.target_eid);
}

static void test_negative_decode_resolve_eid_req()
{
	encode_decode_api_return_code ret;
	struct mctp_ctrl_cmd_resolve_eid_req cmd_resolve_eid;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t target_eid;
	cmd_resolve_eid.ctrl_msg_hdr.command_code =
		MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	ret = mctp_decode_resolve_eid_req(NULL, &ctrl_hdr, &target_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_resolve_eid_req(&cmd_resolve_eid, NULL, &target_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_resolve_eid_req(&cmd_resolve_eid, &ctrl_hdr, NULL);
	assert(ret == INPUT_ERROR);
	cmd_resolve_eid.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_resolve_eid_req(&cmd_resolve_eid, &ctrl_hdr,
					  &target_eid);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_allocate_eid_pool_req()
{
	encode_decode_api_return_code ret;
	struct mctp_ctrl_cmd_allocate_eids_req request;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;
	request.operation = allocation_accepted;
	request.eid_pool_size = 10;
	request.first_eid = 9;

	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
	mctp_ctrl_cmd_allocate_eids_req_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;

	ret = mctp_decode_allocate_endpoint_id_req(&request, &ic_msg_type,
						   &rq_dgram_inst,
						   &command_code, &op,
						   &eid_pool_size, &first_eid);

	assert(ret == DECODE_SUCCESS);
	assert(ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
	assert(rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(command_code == request.ctrl_msg_hdr.command_code);
	assert(op == request.operation);
	assert(eid_pool_size == request.eid_pool_size);
	assert(first_eid == request.first_eid);
}

static void test_negative_decode_allocate_eid_pool_req()
{
	encode_decode_api_return_code ret;
	struct mctp_ctrl_cmd_allocate_eids_req *request = NULL;

	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
	mctp_ctrl_cmd_allocate_eids_req_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;

	ret = mctp_decode_allocate_endpoint_id_req(request, &ic_msg_type,
						   &rq_dgram_inst,
						   &command_code, &op,
						   &eid_pool_size, &first_eid);

	assert(ret == INPUT_ERROR);
}

int main(int argc, char *argv[])
{
	test_decode_resolve_eid_req();
	test_decode_allocate_eid_pool_req();

	/*Negative test cases */
	test_negative_decode_resolve_eid_req();
	test_negative_decode_allocate_eid_pool_req();
	return EXIT_SUCCESS;
}