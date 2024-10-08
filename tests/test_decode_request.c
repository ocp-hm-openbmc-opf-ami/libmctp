#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-decode-request.h"
#include "test_sample_ids.h"

static void test_decode_resolve_eid_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct mctp_ctrl_cmd_resolve_eid_req request;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t target_eid = MCTP_TEST_SAMPLE_ID;
	request.target_eid = 0;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_decode_resolve_eid_req(
		req, sizeof(struct mctp_ctrl_cmd_resolve_eid_req), &ctrl_hdr,
		&target_eid);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code == request.ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
	assert(target_eid == request.target_eid);
}

static void test_negative_decode_resolve_eid_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_resolve_eid_req request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t target_eid;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;

	ret = mctp_decode_resolve_eid_req(
		NULL, sizeof(struct mctp_ctrl_cmd_resolve_eid_req), &ctrl_hdr,
		&target_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_resolve_eid_req(req, 0, &ctrl_hdr, &target_eid);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_resolve_eid_req(
		req, sizeof(struct mctp_ctrl_cmd_resolve_eid_req), NULL,
		&target_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_resolve_eid_req(
		req, sizeof(struct mctp_ctrl_cmd_resolve_eid_req), &ctrl_hdr,
		NULL);
	assert(ret == INPUT_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_resolve_eid_req(
		req, sizeof(struct mctp_ctrl_cmd_resolve_eid_req), &ctrl_hdr,
		&target_eid);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_allocate_eid_pool_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_allocate_eids_req request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;
	request.operation = allocation_accepted;
	request.eid_pool_size = MCTP_TEST_SAMPLE_ID;
	request.first_eid = 9;

	struct mctp_msg *req = (struct mctp_msg *)(&request);
	mctp_ctrl_cmd_allocate_eids_req_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;

	ret = mctp_decode_allocate_endpoint_id_req(
		req, sizeof(struct mctp_ctrl_cmd_allocate_eids_req), &ctrl_hdr,
		&op, &eid_pool_size, &first_eid);

	assert(ret == SUCCESS);
	assert(ctrl_hdr.ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
	assert(ctrl_hdr.rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.command_code == request.ctrl_msg_hdr.command_code);
	assert(op == request.operation);
	assert(eid_pool_size == request.eid_pool_size);
	assert(first_eid == request.first_eid);
}

static void test_negative_decode_allocate_eid_pool_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_allocate_eids_req request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	mctp_ctrl_cmd_allocate_eids_req_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;

	ret = mctp_decode_allocate_endpoint_id_req(
		NULL, sizeof(struct mctp_ctrl_cmd_allocate_eids_req), &ctrl_hdr,
		&op, &eid_pool_size, &first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_req(
		req, sizeof(struct mctp_ctrl_cmd_allocate_eids_req), NULL, &op,
		&eid_pool_size, &first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_req(
		req, sizeof(struct mctp_ctrl_cmd_allocate_eids_req), &ctrl_hdr,
		NULL, &eid_pool_size, &first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_req(
		req, sizeof(struct mctp_ctrl_cmd_allocate_eids_req), &ctrl_hdr,
		&op, NULL, &first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_allocate_endpoint_id_req(
		req, sizeof(struct mctp_ctrl_cmd_allocate_eids_req), &ctrl_hdr,
		&op, &eid_pool_size, NULL);
	assert(ret == INPUT_ERROR);

	ret = mctp_decode_allocate_endpoint_id_req(req, 0, &ctrl_hdr, &op,
						   &eid_pool_size, &first_eid);
	assert(ret == GENERIC_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	ret = mctp_decode_allocate_endpoint_id_req(
		req, sizeof(struct mctp_ctrl_cmd_allocate_eids_req), &ctrl_hdr,
		&op, &eid_pool_size, &first_eid);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_set_eid_req()
{
	encode_decode_rc ret;
	uint8_t eid;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_set_eid request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	mctp_ctrl_cmd_set_eid_op operation;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
	request.operation = set_eid;
	request.eid = MCTP_TEST_SAMPLE_VID;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_decode_set_eid_req(req, sizeof(struct mctp_ctrl_cmd_set_eid),
				      &ctrl_hdr, &operation, &eid);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code == request.ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
	assert(request.operation == operation);
	assert(eid == request.eid);
}

static void test_negative_decode_set_eid_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_set_eid request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t eid = MCTP_TEST_SAMPLE_ID;
	mctp_ctrl_cmd_set_eid_op operation;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;

	ret = mctp_decode_set_eid_req(NULL,
				      sizeof(struct mctp_ctrl_cmd_set_eid),
				      &ctrl_hdr, &operation, &eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_set_eid_req(req, sizeof(struct mctp_ctrl_cmd_set_eid),
				      NULL, &operation, &eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_set_eid_req(req, sizeof(struct mctp_ctrl_cmd_set_eid),
				      &ctrl_hdr, NULL, &eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_set_eid_req(req, sizeof(struct mctp_ctrl_cmd_set_eid),
				      &ctrl_hdr, &operation, NULL);
	assert(ret == INPUT_ERROR);

	ret = mctp_decode_set_eid_req(req, 0, &ctrl_hdr, &operation, &eid);
	assert(ret == GENERIC_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	ret = mctp_decode_set_eid_req(req, sizeof(struct mctp_ctrl_cmd_set_eid),
				      &ctrl_hdr, &operation, &eid);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_uuid_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_get_uuid request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;

	struct mctp_msg *req = (struct mctp_msg *)(&request);
	ret = mctp_decode_get_uuid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_uuid), &ctrl_hdr);
	assert(ret == SUCCESS);
	assert(memcmp(&request.ctrl_msg_hdr, &ctrl_hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
}

static void test_negative_decode_get_uuid_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct mctp_ctrl_cmd_get_uuid request;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	ret = mctp_decode_get_uuid_req(
		NULL, sizeof(struct mctp_ctrl_cmd_get_uuid), &ctrl_hdr);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_uuid_req(req, 0, &ctrl_hdr);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_get_uuid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_uuid), NULL);
	assert(ret == INPUT_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_uuid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_uuid), &ctrl_hdr);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_networkid_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_get_networkid_req request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_NETWORK_ID;

	struct mctp_msg *req = (struct mctp_msg *)(&request);
	ret = mctp_decode_get_networkid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_networkid_req), &ctrl_hdr);
	assert(ret == SUCCESS);
	assert(memcmp(&request.ctrl_msg_hdr, &ctrl_hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
}

static void test_negative_decode_get_networkid_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct mctp_ctrl_cmd_get_networkid_req request;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	ret = mctp_decode_get_networkid_req(
		NULL, sizeof(struct mctp_ctrl_cmd_get_networkid_req),
		&ctrl_hdr);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_networkid_req(req, 0, &ctrl_hdr);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_get_networkid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_networkid_req), NULL);
	assert(ret == INPUT_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_get_networkid_req(
		req, sizeof(struct mctp_ctrl_cmd_get_networkid_req), &ctrl_hdr);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_routing_table_req()
{
	encode_decode_rc ret;
	uint8_t entry_handle;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_get_routing_table_req request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code =
		MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES;
	request.entry_handle = 1;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_decode_get_routing_table_req(
		req, sizeof(struct mctp_ctrl_cmd_get_routing_table_req),
		&ctrl_hdr, &entry_handle);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code == request.ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
	assert(entry_handle == request.entry_handle);
}

static void test_negative_decode_get_routing_table_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_get_routing_table_req request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t entry_handle;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	request.ctrl_msg_hdr.command_code =
		MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES;

	ret = mctp_decode_get_routing_table_req(
		NULL, sizeof(struct mctp_ctrl_cmd_get_routing_table_req),
		&ctrl_hdr, &entry_handle);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_routing_table_req(
		req, sizeof(struct mctp_ctrl_cmd_get_routing_table_req), NULL,
		&entry_handle);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_routing_table_req(
		req, sizeof(struct mctp_ctrl_cmd_get_routing_table_req),
		&ctrl_hdr, NULL);
	assert(ret == INPUT_ERROR);

	ret = mctp_decode_get_routing_table_req(req, 0, &ctrl_hdr,
						&entry_handle);
	assert(ret == GENERIC_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	ret = mctp_decode_get_routing_table_req(
		req, sizeof(struct mctp_ctrl_cmd_get_routing_table_req),
		&ctrl_hdr, &entry_handle);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_ver_support_req()
{
	encode_decode_rc ret = MCTP_TEST_SAMPLE_ENCODE_DECODE_RC_RET_VALUE;
	uint8_t msg_type_number;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_get_mctp_ver_support request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_VERSION_SUPPORT;
	request.msg_type_number = MCTP_TEST_SAMPLE_VID;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_decode_get_ver_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support),
		&ctrl_hdr, &msg_type_number);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code == request.ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
	assert(msg_type_number == request.msg_type_number);
}

static void test_negative_decode_get_ver_support_req()
{
	encode_decode_rc ret = MCTP_TEST_SAMPLE_ENCODE_DECODE_RC_RET_VALUE;
	struct mctp_ctrl_cmd_get_mctp_ver_support request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t msg_type_number;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_decode_get_ver_support_req(
		NULL, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support),
		&ctrl_hdr, &msg_type_number);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_ver_support_req(req, 0, &ctrl_hdr,
					      &msg_type_number);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_get_ver_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support), NULL,
		&msg_type_number);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_ver_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support),
		&ctrl_hdr, NULL);
	assert(ret == INPUT_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_get_ver_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_mctp_ver_support),
		&ctrl_hdr, &msg_type_number);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_eid_req()
{
	encode_decode_rc ret;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_get_eid request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_decode_get_eid_req(req, sizeof(struct mctp_ctrl_cmd_get_eid),
				      &ctrl_hdr);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code == request.ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
}

static void test_negative_decode_get_eid_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_get_eid request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID;

	ret = mctp_decode_get_eid_req(
		NULL, sizeof(struct mctp_ctrl_cmd_get_eid), &ctrl_hdr);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_eid_req(req, sizeof(struct mctp_ctrl_cmd_get_eid),
				      NULL);
	assert(ret == INPUT_ERROR);

	ret = mctp_decode_get_eid_req(req, 0, &ctrl_hdr);
	assert(ret == GENERIC_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	ret = mctp_decode_get_eid_req(req, sizeof(struct mctp_ctrl_cmd_get_eid),
				      &ctrl_hdr);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_get_vdm_support_req()
{
	encode_decode_rc ret;
	uint8_t vid_set_selector;
	const uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_get_vdm_support request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code =
		MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT;
	request.vendor_id_set_selector = MCTP_TEST_SAMPLE_VID;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_decode_get_vdm_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_vdm_support), &ctrl_hdr,
		&vid_set_selector);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code == request.ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
	assert(vid_set_selector == request.vendor_id_set_selector);
}

static void test_negative_decode_get_vdm_support_req()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_get_vdm_support request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t vid_set_selector;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_decode_get_vdm_support_req(
		NULL, sizeof(struct mctp_ctrl_cmd_get_vdm_support), &ctrl_hdr,
		&vid_set_selector);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_vdm_support_req(req, 0, &ctrl_hdr,
					      &vid_set_selector);
	assert(ret == GENERIC_ERROR);
	ret = mctp_decode_get_vdm_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_vdm_support), NULL,
		&vid_set_selector);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_get_vdm_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_vdm_support), &ctrl_hdr,
		NULL);
	assert(ret == INPUT_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_get_vdm_support_req(
		req, sizeof(struct mctp_ctrl_cmd_get_vdm_support), &ctrl_hdr,
		&vid_set_selector);
	assert(ret == GENERIC_ERROR);
}

static void test_decode_prepare_endpoint_discovery_req()
{
	encode_decode_rc ret = MCTP_TEST_SAMPLE_ENCODE_DECODE_RC_RET_VALUE;
	uint8_t expected_instance_id = MCTP_TEST_SAMPLE_INSTANCE_ID;
	struct mctp_ctrl_cmd_prepare_for_endpoint_discovery request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	request.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	request.ctrl_msg_hdr.rq_dgram_inst = rq_d_inst;
	request.ctrl_msg_hdr.command_code =
		MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY;
	struct mctp_msg *req = (struct mctp_msg *)(&request);

	ret = mctp_decode_prepare_endpoint_discovery_req(
		req,
		sizeof(struct mctp_ctrl_cmd_prepare_for_endpoint_discovery),
		&ctrl_hdr);
	assert(ret == SUCCESS);
	assert(ctrl_hdr.command_code == request.ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
}

static void test_negative_decode_prepare_endpoint_discovery_req()
{
	encode_decode_rc ret = MCTP_TEST_SAMPLE_ENCODE_DECODE_RC_RET_VALUE;
	struct mctp_ctrl_cmd_prepare_for_endpoint_discovery request;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	struct mctp_msg *req = (struct mctp_msg *)(&request);
	request.ctrl_msg_hdr.command_code =
		MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY;

	ret = mctp_decode_prepare_endpoint_discovery_req(
		NULL,
		sizeof(struct mctp_ctrl_cmd_prepare_for_endpoint_discovery),
		&ctrl_hdr);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_prepare_endpoint_discovery_req(
		req,
		sizeof(struct mctp_ctrl_cmd_prepare_for_endpoint_discovery),
		NULL);
	assert(ret == INPUT_ERROR);
	ret = mctp_decode_prepare_endpoint_discovery_req(req, 0, &ctrl_hdr);
	assert(ret == GENERIC_ERROR);
	request.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	ret = mctp_decode_prepare_endpoint_discovery_req(
		req,
		sizeof(struct mctp_ctrl_cmd_prepare_for_endpoint_discovery),
		&ctrl_hdr);
	assert(ret == GENERIC_ERROR);
}

int main(int argc, char *argv[])
{
	test_decode_resolve_eid_req();
	test_decode_allocate_eid_pool_req();
	test_decode_set_eid_req();
	test_decode_get_uuid_req();
	test_decode_get_networkid_req();
	test_decode_get_routing_table_req();
	test_decode_get_ver_support_req();
	test_decode_get_eid_req();
	test_decode_get_vdm_support_req();
	test_decode_prepare_endpoint_discovery_req();

	/*Negative test cases */
	test_negative_decode_resolve_eid_req();
	test_negative_decode_allocate_eid_pool_req();
	test_negative_decode_set_eid_req();
	test_negative_decode_get_uuid_req();
	test_negative_decode_get_networkid_req();
	test_negative_decode_get_routing_table_req();
	test_negative_decode_get_ver_support_req();
	test_negative_decode_get_eid_req();
	test_negative_decode_get_vdm_support_req();
	test_negative_decode_prepare_endpoint_discovery_req();

	return EXIT_SUCCESS;
}
