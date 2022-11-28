#include <assert.h>
#include <stdlib.h>

#include "libmctp-cmds.h"
#include "libmctp-encode-request.h"

static void test_encode_resolve_eid_req()
{
	encode_rc ret;
	const uint8_t target_eid = 9;
	const uint8_t instance_id = 0x01;
	struct mctp_ctrl_cmd_resolve_eid_req request;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	ret = mctp_encode_resolve_eid_req(
		req, sizeof(struct mctp_ctrl_cmd_resolve_eid_req),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), target_eid);
	assert(ret == ENCODE_SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst ==
	       (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.target_eid == target_eid);
}

static void test_negative_encode_resolve_eid_req()
{
	encode_rc ret;
	struct mctp_msg request;
	const uint8_t target_eid = 9;
	const uint8_t instance_id = 0x01;

	ret = mctp_encode_resolve_eid_req(
		NULL, sizeof(struct mctp_ctrl_cmd_resolve_eid_req),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), target_eid);
	assert(ret == ENCODE_INPUT_ERROR);
	ret = mctp_encode_resolve_eid_req(
		&request, 0, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		target_eid);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_allocate_eid_pool_req()
{
	encode_rc ret;
	const uint8_t first_eid = 9;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_req_op operation = allocate_eids;
	struct mctp_ctrl_cmd_allocate_eids_req request;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_allocate_endpoint_id_req(
		req, sizeof(struct mctp_ctrl_cmd_allocate_eids_req), rq_d_inst,
		operation, eid_pool_size, first_eid);
	assert(ret == ENCODE_SUCCESS);
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
	encode_rc ret;
	uint8_t sample_eid = 10;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_req_op operation = allocate_eids;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_allocate_endpoint_id_req(
		request, sizeof(struct mctp_ctrl_cmd_allocate_eids_req),
		rq_d_inst, operation, eid_pool_size, sample_eid);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_allocate_endpoint_id_req(
		&request1, 0, rq_d_inst, operation, eid_pool_size, sample_eid);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_set_eid_req()
{
	encode_rc ret;
	const uint8_t eid = 9;
	uint8_t expected_instance_id = 0x01;
	struct mctp_ctrl_cmd_set_eid request;
	mctp_ctrl_cmd_set_eid_op operation = set_eid;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_set_eid_req(req, sizeof(struct mctp_ctrl_cmd_set_eid),
				      rq_d_inst, operation, eid);
	assert(ret == ENCODE_SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.operation == operation);
	assert(request.eid == eid);
}

static void test_negative_encode_set_eid_req()
{
	encode_rc ret;
	uint8_t eid = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_set_eid_op operation = set_eid;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;
	ret = mctp_encode_set_eid_req(request,
				      sizeof(struct mctp_ctrl_cmd_set_eid),
				      rq_d_inst, operation, eid);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_set_eid_req(&request1, 0, rq_d_inst, operation, eid);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_get_uuid_req()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	struct mctp_ctrl_cmd_get_uuid request;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_uuid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_uuid), rq_d_inst);
	assert(ret == ENCODE_SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

static void test_negative_encode_get_uuid_req()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_get_uuid_req(
		request, sizeof(struct mctp_ctrl_cmd_get_uuid), rq_d_inst);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_uuid_req(&request1, 0, rq_d_inst);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_get_networkid_req()
{
	encode_rc ret;
	uint8_t instance_id = 0x01;
	struct mctp_ctrl_cmd_get_networkid_req request;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_networkid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_networkid_req),
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(ret == ENCODE_SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_NETWORK_ID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst ==
	       (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

static void test_negative_encode_get_networkid_req()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_get_networkid_req(
		request, sizeof(struct mctp_ctrl_cmd_get_networkid_req),
		rq_d_inst);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_networkid_req(&request1, 0, rq_d_inst);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_get_routing_table_req()
{
	encode_rc ret;
	uint8_t entry_handle = 1;
	uint8_t expected_instance_id = 0x01;
	struct mctp_ctrl_cmd_get_routing_table_req request;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_routing_table_req(
		req, sizeof(struct mctp_ctrl_cmd_get_routing_table_req),
		rq_d_inst, entry_handle);
	assert(ret == ENCODE_SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.entry_handle == entry_handle);
}

static void test_negative_encode_get_routing_table_req()
{
	encode_rc ret;
	uint8_t entry_handle = 1;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;
	ret = mctp_encode_get_routing_table_req(
		request, sizeof(struct mctp_ctrl_cmd_get_routing_table_req),
		rq_d_inst, entry_handle);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_routing_table_req(&request1, 0, rq_d_inst,
						entry_handle);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_get_ver_support_req()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t msg_type_number = 10;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_ctrl_cmd_get_mctp_ver_support request;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_ver_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support),
		rq_d_inst, msg_type_number);
	assert(ret == ENCODE_SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(request.msg_type_number == msg_type_number);
}

static void test_negative_encode_get_ver_support_req()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t msg_type_number = 10;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;
	ret = mctp_encode_get_ver_support_req(
		request, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support),
		rq_d_inst, msg_type_number);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_ver_support_req(&request1, 0, rq_d_inst,
					      msg_type_number);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_get_eid_req()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	struct mctp_ctrl_cmd_get_eid request;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_get_eid_req(req, sizeof(struct mctp_ctrl_cmd_get_eid),
				      rq_d_inst);
	assert(ret == ENCODE_SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

static void test_negative_encode_get_eid_req()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_get_eid_req(
		request, sizeof(struct mctp_ctrl_cmd_get_eid), rq_d_inst);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_eid_req(&request1, 0, rq_d_inst);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_endpoint_discovery_req()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	struct mctp_ctrl_cmd_endpoint_discovery_req request;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_encode_endpoint_discovery_req(
		req, sizeof(struct mctp_ctrl_cmd_endpoint_discovery_req),
		rq_d_inst);
	assert(ret == ENCODE_SUCCESS);
	assert(request.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_ENDPOINT_DISCOVERY);
	assert(request.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(request.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

static void test_negative_encode_endpoint_discovery_req()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *request = NULL;

	ret = mctp_encode_endpoint_discovery_req(
		request, sizeof(struct mctp_ctrl_cmd_endpoint_discovery_req),
		rq_d_inst);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_endpoint_discovery_req(&request1, 0, rq_d_inst);
	assert(ret == ENCODE_GENERIC_ERROR);
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
	test_encode_endpoint_discovery_req();

	/*Negative test cases */
	test_negative_encode_resolve_eid_req();
	test_negative_encode_allocate_eid_pool_req();
	test_negative_encode_set_eid_req();
	test_negative_encode_get_uuid_req();
	test_negative_encode_get_networkid_req();
	test_negative_encode_get_routing_table_req();
	test_negative_encode_get_ver_support_req();
	test_negative_encode_get_eid_req();
	test_negative_encode_endpoint_discovery_req();

	return EXIT_SUCCESS;
}