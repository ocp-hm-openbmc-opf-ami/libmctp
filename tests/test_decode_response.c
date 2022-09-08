#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-decode-response.h"

static void test_decode_resolve_eid_resp()
{
	encode_decode_api_return_code ret;
	uint8_t packed_packet[] = { 0,
				    1,
				    (uint8_t)MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID,
				    (uint8_t)MCTP_CTRL_CC_SUCCESS,
				    10,
				    12 };
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
	assert(completion_code == response->completion_code);
	assert(bridge_eid == response->bridge_eid);
	assert(!memcmp(address.data,
		       (uint8_t *)response +
			       sizeof(struct mctp_ctrl_cmd_resolve_eid_resp),
		       address.data_size));
	assert(address.data_size ==
	       sizeof(packed_packet) -
		       sizeof(struct mctp_ctrl_cmd_resolve_eid_resp));
}

static void test_negative_decode_resolve_eid_resp()
{
	encode_decode_api_return_code ret;
	uint8_t packed_packet[] = { 0,
				    1,
				    (uint8_t)MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID,
				    (uint8_t)MCTP_CTRL_CC_SUCCESS,
				    10,
				    12 };
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
	encode_decode_api_return_code ret;
	struct mctp_ctrl_cmd_allocate_eids_resp response;
	response.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	response.ctrl_hdr.rq_dgram_inst = rq_d_inst;
	response.ctrl_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;
	response.completion_code = MCTP_CTRL_CC_SUCCESS;
	response.operation = allocation_accepted;
	response.eid_pool_size = 10;
	response.first_eid = 9;

	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
	uint8_t cc;
	mctp_ctrl_cmd_allocate_eids_resp_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_decode_allocate_endpoint_id_resp(
		resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ic_msg_type, &rq_dgram_inst, &command_code, &cc, &op,
		&eid_pool_size, &first_eid);

	assert(ret == DECODE_SUCCESS);
	assert(ic_msg_type == response.ctrl_hdr.ic_msg_type);
	assert(rq_dgram_inst == response.ctrl_hdr.rq_dgram_inst);
	assert(command_code == response.ctrl_hdr.command_code);
	assert(cc == response.completion_code);
	assert(op == response.operation);
	assert(eid_pool_size == response.eid_pool_size);
	assert(first_eid == response.first_eid);
}

static void test_negative_decode_allocate_eid_pool_resp()
{
	encode_decode_api_return_code ret;
	struct mctp_msg *response = NULL;

	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
	uint8_t cc;
	mctp_ctrl_cmd_allocate_eids_resp_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;

	ret = mctp_decode_allocate_endpoint_id_resp(
		response, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
		&ic_msg_type, &rq_dgram_inst, &command_code, &cc, &op,
		&eid_pool_size, &first_eid);
	assert(ret == INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_decode_allocate_endpoint_id_resp(&response1, 0, &ic_msg_type,
						    &rq_dgram_inst,
						    &command_code, &cc, &op,
						    &eid_pool_size, &first_eid);
	assert(ret == GENERIC_ERROR);
}

int main(int argc, char *argv[])
{
	test_decode_resolve_eid_resp();
	test_decode_allocate_eid_pool_resp();

	/*Negative test cases */
	test_negative_decode_resolve_eid_resp();
	test_negative_decode_allocate_eid_pool_resp();
	return EXIT_SUCCESS;
}