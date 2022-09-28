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

static void test_encode_set_eid_resp()
{
	encode_decode_api_return_code ret;
	struct mctp_ctrl_resp_set_eid response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	ctrl_hdr.rq_dgram_inst = rq_d_inst;
	ctrl_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
	uint8_t eid_pool_size = 10;
	uint8_t eid_set = 9;
	uint8_t status = 8;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_set_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, eid_pool_size, status,
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
	encode_decode_api_return_code ret;
	struct mctp_msg *response = NULL;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	ctrl_hdr.rq_dgram_inst = rq_d_inst;
	ctrl_hdr.command_code = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
	uint8_t eid_pool_size = 9;
	uint8_t eid_set = 10;
	uint8_t status = 8;
	ret = mctp_encode_set_eid_resp(response,
				       sizeof(struct mctp_ctrl_resp_set_eid),
				       &ctrl_hdr, eid_pool_size, status,
				       eid_set);
	assert(ret == INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_set_eid_resp(&response1, 0, &ctrl_hdr, eid_pool_size,
				       status, eid_set);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_get_uuid_resp()
{
	encode_decode_api_return_code ret;
	struct mctp_ctrl_resp_get_uuid response;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	ctrl_hdr.rq_dgram_inst = rq_d_inst;
	ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;
	/* 16 byte UUID */
	char sample_uuid[16] = "61a3";
	guid_t test_uuid;

	/*doing memcpy of string literal*/
	memcpy(&test_uuid.raw, sample_uuid, sizeof(guid_t));
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	ret = mctp_encode_get_uuid_resp(resp,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, &test_uuid);
	assert(ret == ENCODE_SUCCESS);

	assert(response.ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(memcmp(response.uuid.raw, test_uuid.raw, sizeof(guid_t)) == 0);
}

static void test_negative_encode_get_uuid_resp()
{
	encode_decode_api_return_code ret;
	struct mctp_msg *response = NULL;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	ctrl_hdr.rq_dgram_inst = rq_d_inst;
	ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;
	guid_t test_uuid;

	ret = mctp_encode_get_uuid_resp(response,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, &test_uuid);
	assert(ret == INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_get_uuid_resp(&response1, 0, &ctrl_hdr, &test_uuid);
	assert(ret == GENERIC_ERROR);
	ret = mctp_encode_get_uuid_resp(&response1,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					NULL, &test_uuid);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_get_uuid_resp(&response1,
					sizeof(struct mctp_ctrl_resp_get_uuid),
					&ctrl_hdr, NULL);
	assert(ret == INPUT_ERROR);
}

static void test_encode_get_networkid_resp()
{
	encode_decode_api_return_code ret = false;
	struct mctp *mctp;
	mctp = mctp_init();
	guid_t networkid;
	guid_t retrieved_networkid;
	networkid.canonical.data1 = 10;
	struct mctp_ctrl_get_networkid_resp response;

	assert(mctp_set_networkid(mctp, &networkid));

	assert(mctp_get_networkid(mctp, &retrieved_networkid));
	assert(networkid.canonical.data1 ==
	       retrieved_networkid.canonical.data1);
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	ret = mctp_encode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp), &networkid);
	assert(ret == ENCODE_SUCCESS);
	assert(response.completion_code == MCTP_CTRL_CC_SUCCESS);
	assert(response.networkid.canonical.data1 == networkid.canonical.data1);
	mctp_destroy(mctp);
}

static void test_negative_decode_get_networkid_resp()
{
	encode_decode_api_return_code ret;
	struct mctp_msg *response = NULL;
	guid_t networkid;

	ret = mctp_encode_get_networkid_resp(
		response, sizeof(struct mctp_ctrl_get_networkid_resp),
		&networkid);
	assert(ret == INPUT_ERROR);
	struct mctp_msg request1;
	ret = mctp_encode_get_networkid_resp(&request1, 0, &networkid);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_get_routing_table_resp(void)
{
	struct get_routing_table_entry_with_address entries[1];
	entries[0].routing_info.eid_range_size = 1;
	entries[0].routing_info.starting_eid = 9;
	entries[0].routing_info.entry_type = 2;
	entries[0].routing_info.phys_transport_binding_id = 1;
	entries[0].routing_info.phys_media_type_id = 4;
	entries[0].routing_info.phys_address_size = 1;
	entries[0].phys_address[0] = 0x12;

	struct mctp_ctrl_resp_get_routing_table response;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	size_t new_size = 0;
	uint8_t next_entry_handle = 0x01;

	assert(ENCODE_SUCCESS ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, &new_size, next_entry_handle));
	next_entry_handle = 0xFF;
	assert(ENCODE_SUCCESS ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, &new_size, next_entry_handle));

	size_t exp_new_size =
		sizeof(struct mctp_ctrl_resp_get_routing_table) +
		sizeof(struct get_routing_table_entry_with_address) +
		entries[0].routing_info.phys_address_size -
		sizeof(entries[0].phys_address);
	assert(new_size == exp_new_size);
	assert(response.completion_code == MCTP_CTRL_CC_SUCCESS);
	assert(response.next_entry_handle == 0xFF);
	assert(response.number_of_entries == 0x01);
	next_entry_handle = 0xFF;

	assert(INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       NULL, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, &new_size, next_entry_handle));
	assert(INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       NULL, 1, &new_size, next_entry_handle));
	assert(INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, NULL, next_entry_handle));
	assert(ENCODE_SUCCESS ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 0, &new_size, next_entry_handle));

	next_entry_handle = 0x01;

	assert(INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       NULL, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, &new_size, next_entry_handle));
	assert(INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       NULL, 1, &new_size, next_entry_handle));
	assert(INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, NULL, next_entry_handle));
	assert(ENCODE_SUCCESS ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 0, &new_size, next_entry_handle));
}

int main(int argc, char *argv[])
{
	test_mctp_encode_resolve_eid_resp();
	test_encode_allocate_eid_pool_resp();
	test_encode_set_eid_resp();
	test_encode_get_uuid_resp();
	test_encode_get_networkid_resp();
	test_encode_get_routing_table_resp();

	/*Negative test cases */
	test_negative_encode_resolve_eid_resp();
	test_negative_encode_allocate_eid_pool_resp();
	test_negative_encode_set_eid_resp();
	test_negative_encode_get_uuid_resp();
	test_negative_decode_get_networkid_resp();

	return EXIT_SUCCESS;
}