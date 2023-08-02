#include <assert.h>
#include <stdlib.h>

#include "libmctp-cmds.h"
#include "libmctp-encode-request.h"
#include "test_sample_ids.h"

// Initialize with invalid values
struct mctp_ctrl_msg_hdr invalid_header = { 0x01, 0x00, 0xF0 };

static void test_encode_resolve_eid_req()
{
	encode_decode_rc ret;
	const uint8_t target_eid = MCTP_TEST_SAMPLE_EID;
	const uint8_t instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_resolve_eid_req request;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	ret = mctp_encode_resolve_eid_req(
		req, sizeof(struct mctp_ctrl_cmd_resolve_eid_req),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), target_eid);
	assert(ret == SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst ==
	       (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.target_eid == target_eid);
}

static void test_negative_encode_resolve_eid_req()
{
	encode_decode_rc ret;
	struct mctp_msg request;
	const uint8_t target_eid = MCTP_TEST_SAMPLE_EID;
	const uint8_t instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;

	ret = mctp_encode_resolve_eid_req(
		NULL, sizeof(struct mctp_ctrl_cmd_resolve_eid_req),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), target_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_resolve_eid_req(
		&request, 0, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		target_eid);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_allocate_eid_pool_req()
{
	encode_decode_rc ret;
	const uint8_t first_eid = MCTP_TEST_SAMPLE_EID;
	const uint8_t eid_pool_size = MCTP_TEST_SAMPLE_EID_POOL_SIZE;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	mctp_ctrl_cmd_allocate_eids_req_op operation = allocate_eids;
	struct mctp_ctrl_cmd_allocate_eids_req request;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_allocate_endpoint_id_req(
		req, sizeof(struct mctp_ctrl_cmd_allocate_eids_req), rq_d_inst,
		operation, eid_pool_size, first_eid);
	assert(ret == SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.operation == operation);
	assert(request.eid_pool_size == eid_pool_size);
	assert(request.first_eid == first_eid);
}

static void test_negative_encode_allocate_eid_pool_req()
{
	encode_decode_rc ret;
	uint8_t sample_eid = MCTP_TEST_SAMPLE_EID;
	const uint8_t eid_pool_size = MCTP_TEST_SAMPLE_EID_POOL_SIZE;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	mctp_ctrl_cmd_allocate_eids_req_op operation = allocate_eids;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_allocate_endpoint_id_req(
		request, sizeof(struct mctp_ctrl_cmd_allocate_eids_req),
		rq_d_inst, operation, eid_pool_size, sample_eid);
	assert(ret == INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_allocate_endpoint_id_req(
		&request1, 0, rq_d_inst, operation, eid_pool_size, sample_eid);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_set_eid_req()
{
	encode_decode_rc ret;
	const uint8_t eid = MCTP_TEST_SAMPLE_EID;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_set_eid request;
	mctp_ctrl_cmd_set_eid_op operation = set_eid;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_set_eid_req(req, sizeof(struct mctp_ctrl_cmd_set_eid),
				      rq_d_inst, operation, eid);
	assert(ret == SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.operation == operation);
	assert(request.eid == eid);
}

static void test_negative_encode_set_eid_req()
{
	encode_decode_rc ret;
	uint8_t eid = MCTP_TEST_SAMPLE_EID;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	mctp_ctrl_cmd_set_eid_op operation = set_eid;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;
	ret = mctp_encode_set_eid_req(request,
				      sizeof(struct mctp_ctrl_cmd_set_eid),
				      rq_d_inst, operation, eid);
	assert(ret == INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_set_eid_req(&request1, 0, rq_d_inst, operation, eid);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_get_uuid_req()
{
	encode_decode_rc ret;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_get_uuid request;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_uuid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_uuid), rq_d_inst);
	assert(ret == SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

static void test_negative_encode_get_uuid_req()
{
	encode_decode_rc ret;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_get_uuid_req(
		request, sizeof(struct mctp_ctrl_cmd_get_uuid), rq_d_inst);
	assert(ret == INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_uuid_req(&request1, 0, rq_d_inst);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_get_networkid_req()
{
	encode_decode_rc ret;
	const uint8_t instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_get_networkid_req request;
	request.ctrl_msg_hdr = invalid_header;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_networkid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_networkid_req),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(ret == SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_NETWORK_ID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst ==
	       (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

static void test_negative_encode_get_networkid_req()
{
	encode_decode_rc ret;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_get_networkid_req(
		request, sizeof(struct mctp_ctrl_cmd_get_networkid_req),
		rq_d_inst);
	assert(ret == INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_networkid_req(&request1, 0, rq_d_inst);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_get_routing_table_req()
{
	encode_decode_rc ret;
	uint8_t entry_handle = 1;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_get_routing_table_req request;
	request.ctrl_msg_hdr = invalid_header;
	request.entry_handle = 0x80;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_routing_table_req(
		req, sizeof(struct mctp_ctrl_cmd_get_routing_table_req),
		rq_d_inst, entry_handle);
	assert(ret == SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.entry_handle == entry_handle);
}

static void test_negative_encode_get_routing_table_req()
{
	encode_decode_rc ret;
	uint8_t entry_handle = 1;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;
	ret = mctp_encode_get_routing_table_req(
		request, sizeof(struct mctp_ctrl_cmd_get_routing_table_req),
		rq_d_inst, entry_handle);
	assert(ret == INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_routing_table_req(&request1, 0, rq_d_inst,
						entry_handle);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_get_ver_support_req()
{
	encode_decode_rc ret = MCTP_TEST_SAMPLE_ENCODE_DECODE_RC_RET_VALUE;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t msg_type_number = MCTP_TEST_SAMPLE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_ctrl_cmd_get_mctp_ver_support request;
	request.ctrl_msg_hdr = invalid_header;
	request.msg_type_number = 0x80;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_ver_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support),
		rq_d_inst, msg_type_number);
	assert(ret == SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.msg_type_number == msg_type_number);
}

static void test_negative_encode_get_ver_support_req()
{
	encode_decode_rc ret = MCTP_TEST_SAMPLE_ENCODE_DECODE_RC_RET_VALUE;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t msg_type_number = MCTP_TEST_SAMPLE_MSG_TYPE_NUMBER;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;
	ret = mctp_encode_get_ver_support_req(
		request, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support),
		rq_d_inst, msg_type_number);
	assert(ret == INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_ver_support_req(&request1, 0, rq_d_inst,
					      msg_type_number);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_get_eid_req()
{
	encode_decode_rc ret;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_get_eid request;
	request.ctrl_msg_hdr = invalid_header;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_eid_req(req, sizeof(struct mctp_ctrl_cmd_get_eid),
				      rq_d_inst);
	assert(ret == SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

static void test_negative_encode_get_eid_req()
{
	encode_decode_rc ret;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_get_eid_req(
		request, sizeof(struct mctp_ctrl_cmd_get_eid), rq_d_inst);
	assert(ret == INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_eid_req(&request1, 0, rq_d_inst);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_get_vdm_support_req()
{
	encode_decode_rc ret;
	uint8_t vid_set_selector = MCTP_TEST_SAMPLE_VID;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_get_vdm_support request;
	request.ctrl_msg_hdr = invalid_header;
	request.vendor_id_set_selector = 0x00;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_vdm_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_vdm_support), rq_d_inst,
		vid_set_selector);
	assert(ret == SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.vendor_id_set_selector == vid_set_selector);
}

static void test_negative_encode_get_vdm_support_req()
{
	encode_decode_rc ret;
	uint8_t vid_set_selector = MCTP_TEST_SAMPLE_VID;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_get_vdm_support_req(
		request, sizeof(struct mctp_ctrl_cmd_get_vdm_support),
		rq_d_inst, vid_set_selector);
	assert(ret == INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_vdm_support_req(&request1, 0, rq_d_inst,
					      vid_set_selector);
	assert(ret == GENERIC_ERROR);
}

int main(int argc, char *argv[])
{
	test_encode_resolve_eid_req();
	test_encode_allocate_eid_pool_req();
	test_encode_set_eid_req();
	test_encode_get_uuid_req();
	test_encode_get_networkid_req();
	test_encode_get_routing_table_req();
	test_encode_get_ver_support_req();
	test_encode_get_eid_req();
	test_encode_get_vdm_support_req();

	/*Negative test cases */
	test_negative_encode_resolve_eid_req();
	test_negative_encode_allocate_eid_pool_req();
	test_negative_encode_set_eid_req();
	test_negative_encode_get_uuid_req();
	test_negative_encode_get_networkid_req();
	test_negative_encode_get_routing_table_req();
	test_negative_encode_get_ver_support_req();
	test_negative_encode_get_eid_req();
	test_negative_encode_get_vdm_support_req();

	return EXIT_SUCCESS;
}
