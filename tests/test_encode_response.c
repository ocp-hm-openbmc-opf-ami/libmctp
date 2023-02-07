#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-encode-response.h"

static void test_encode_resolve_eid_resp()
{
	encode_decode_rc ret;
	uint8_t phy_address[] = { 10, 12, 13 };
	struct mctp_ctrl_cmd_resolve_eid_resp *response;
	struct variable_field address;
	size_t length = sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) +
			sizeof(phy_address);
	address.data = phy_address;
	address.data_size = sizeof(phy_address);
	response = (struct mctp_ctrl_cmd_resolve_eid_resp *)malloc(
		sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) +
		sizeof(phy_address));
	const uint8_t instance_id = 0x01;
	uint8_t rq_d_inst = instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	const uint8_t bridge_eid = 10;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	struct mctp_msg *resp = (struct mctp_msg *)(response);

	ret = mctp_encode_resolve_eid_resp(resp, &length, rq_d_inst,
					   completion_code, bridge_eid,
					   &address);
	assert(ret == SUCCESS);
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
	encode_decode_rc ret;
	struct mctp_msg response;
	uint8_t phy_address[] = { 10, 12, 13 };
	struct variable_field address;
	size_t temp_length = 0;
	size_t length = sizeof(struct mctp_ctrl_cmd_resolve_eid_resp) +
			sizeof(phy_address);
	address.data = phy_address;
	address.data_size = sizeof(phy_address);
	const uint8_t instance_id = 0x01;
	const uint8_t bridge_eid = 10;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	ret = mctp_encode_resolve_eid_resp(
		NULL, &length, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		completion_code, bridge_eid, &address);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_resolve_eid_resp(
		&response, NULL, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		completion_code, bridge_eid, &address);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_resolve_eid_resp(
		&response, &length, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		completion_code, bridge_eid, NULL);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_resolve_eid_resp(
		&response, &temp_length,
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), completion_code,
		bridge_eid, &address);
	assert(ret == GENERIC_ERROR);
	address.data = NULL;
	address.data_size = 0;
	ret = mctp_encode_resolve_eid_resp(
		&response, &length, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		completion_code, bridge_eid, &address);
	assert(ret == INPUT_ERROR);
}

static void test_encode_allocate_eid_pool_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_cmd_allocate_eids_resp response;
	size_t length = sizeof(struct mctp_ctrl_cmd_allocate_eids_resp);
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	mctp_ctrl_cmd_allocate_eids_resp_op op = allocation_accepted;
	uint8_t eid_pool_size = 10;
	uint8_t first_eid = 9;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_allocate_endpoint_id_resp(resp, &length, rq_d_inst,
						    op, completion_code,
						    eid_pool_size, first_eid);
	assert(ret == SUCCESS);

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
	encode_decode_rc ret;
	struct mctp_msg *response = NULL;
	size_t temp_length = 0;
	size_t length = sizeof(struct mctp_ctrl_cmd_allocate_eids_resp);
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	mctp_ctrl_cmd_allocate_eids_resp_op op = allocation_accepted;
	uint8_t eid_pool_size = 10;
	uint8_t first_eid = 9;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;

	ret = mctp_encode_allocate_endpoint_id_resp(response, &length,
						    rq_d_inst, op,
						    completion_code,
						    eid_pool_size, first_eid);
	assert(ret == INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_allocate_endpoint_id_resp(&response1, NULL, rq_d_inst,
						    op, completion_code,
						    eid_pool_size, first_eid);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_allocate_endpoint_id_resp(&response1, &temp_length,
						    rq_d_inst, op,
						    completion_code,
						    eid_pool_size, first_eid);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_set_eid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_resp_set_eid response;
	size_t length = sizeof(struct mctp_ctrl_resp_set_eid);
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	uint8_t eid_pool_size = 10;
	uint8_t eid_set = 9;
	uint8_t status = 8;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_set_eid_resp(resp, &length, rq_d_inst,
				       completion_code, eid_pool_size, status,
				       eid_set);
	assert(ret == SUCCESS);

	assert(response.ctrl_hdr.command_code == MCTP_CTRL_CMD_SET_ENDPOINT_ID);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response.status == status);
	assert(response.eid_pool_size == eid_pool_size);
	assert(response.eid_set == eid_set);
}

static void test_negative_encode_set_eid_resp()
{
	encode_decode_rc ret;
	struct mctp_msg *response = NULL;
	size_t temp_length = 0;
	size_t length = sizeof(struct mctp_ctrl_resp_set_eid);
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	uint8_t eid_pool_size = 9;
	uint8_t eid_set = 10;
	uint8_t status = 8;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	ret = mctp_encode_set_eid_resp(response, &length, rq_d_inst,
				       completion_code, eid_pool_size, status,
				       eid_set);
	assert(ret == INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_set_eid_resp(&response1, NULL, rq_d_inst,
				       completion_code, eid_pool_size, status,
				       eid_set);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_set_eid_resp(&response1, &temp_length, rq_d_inst,
				       completion_code, eid_pool_size, status,
				       eid_set);
	assert(ret == GENERIC_ERROR);
}

static void test_encode_get_uuid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_resp_get_uuid response;
	size_t length = sizeof(struct mctp_ctrl_resp_get_uuid);
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	/* 16 byte UUID */
	char sample_uuid[16] = "61a3";
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	guid_t test_uuid;

	/*doing memcpy of string literal*/
	memcpy(&test_uuid.raw, sample_uuid, sizeof(guid_t));
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	ret = mctp_encode_get_uuid_resp(resp, &length, rq_d_inst,
					completion_code, &test_uuid);
	assert(ret == SUCCESS);

	assert(response.ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(memcmp(response.uuid.raw, test_uuid.raw, sizeof(guid_t)) == 0);
}

static void test_negative_encode_get_uuid_resp()
{
	encode_decode_rc ret;
	struct mctp_msg *response = NULL;
	size_t temp_length = 0;
	size_t length = sizeof(struct mctp_ctrl_resp_get_uuid);
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	guid_t test_uuid;

	ret = mctp_encode_get_uuid_resp(response, &length, rq_d_inst,
					completion_code, &test_uuid);
	assert(ret == INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_get_uuid_resp(&response1, NULL, rq_d_inst,
					completion_code, &test_uuid);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_get_uuid_resp(&response1, &temp_length, rq_d_inst,
					completion_code, &test_uuid);
	assert(ret == GENERIC_ERROR);
	ret = mctp_encode_get_uuid_resp(&response1, &length, rq_d_inst,
					completion_code, NULL);
	assert(ret == INPUT_ERROR);
}

static void test_encode_get_networkid_resp()
{
	encode_decode_rc ret = false;
	struct mctp *mctp;
	size_t length = sizeof(struct mctp_ctrl_get_networkid_resp);
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	char sample_guid[16] = "61a3";
	mctp = mctp_init();
	guid_t networkid;
	guid_t retrieved_networkid;
	networkid.canonical.data1 = 10;
	struct mctp_ctrl_get_networkid_resp response;
	memcpy(&networkid.raw, sample_guid, sizeof(guid_t));
	assert(mctp_set_networkid(mctp, &networkid));

	assert(mctp_get_networkid(mctp, &retrieved_networkid));
	assert(networkid.canonical.data1 ==
	       retrieved_networkid.canonical.data1);
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	ret = mctp_encode_get_networkid_resp(resp, &length, completion_code,
					     &networkid);
	assert(ret == SUCCESS);
	assert(response.completion_code == MCTP_CTRL_CC_SUCCESS);
	assert(response.networkid.canonical.data1 == networkid.canonical.data1);
	assert(memcmp(response.networkid.raw, networkid.raw, sizeof(guid_t)) ==
	       0);
	mctp_destroy(mctp);
}

static void test_negative_encode_get_networkid_resp()
{
	encode_decode_rc ret;
	struct mctp_msg response;
	size_t temp_length = 0;
	size_t length = sizeof(struct mctp_ctrl_get_networkid_resp);
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	guid_t networkid;

	ret = mctp_encode_get_networkid_resp(NULL, &length, completion_code,
					     &networkid);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_get_networkid_resp(&response, NULL, completion_code,
					     &networkid);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_get_networkid_resp(&response, &temp_length,
					     completion_code, &networkid);
	assert(ret == GENERIC_ERROR);
	ret = mctp_encode_get_networkid_resp(&response, &length,
					     completion_code, NULL);
	assert(ret == INPUT_ERROR);
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
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	size_t length = sizeof(struct mctp_ctrl_resp_get_routing_table);

	assert(SUCCESS == mctp_encode_get_routing_table_resp(
				  resp, &length, completion_code, entries, 1,
				  next_entry_handle, &new_size));
	next_entry_handle = 0xFF;
	assert(SUCCESS == mctp_encode_get_routing_table_resp(
				  resp, &length, completion_code, entries, 1,
				  next_entry_handle, &new_size));

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

	assert(SUCCESS == mctp_encode_get_routing_table_resp(
				  resp, &length, completion_code, entries, 0,
				  next_entry_handle, &new_size));

	next_entry_handle = 0x01;
	assert(SUCCESS == mctp_encode_get_routing_table_resp(
				  resp, &length, completion_code, entries, 0,
				  next_entry_handle, &new_size));
}

static void test_negative_encode_get_routing_table_resp()
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
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	size_t temp_length = 0;
	size_t length = sizeof(struct mctp_ctrl_resp_get_routing_table);

	assert(INPUT_ERROR == mctp_encode_get_routing_table_resp(
				      NULL, &length, completion_code, entries,
				      1, next_entry_handle, &new_size));
	assert(INPUT_ERROR == mctp_encode_get_routing_table_resp(
				      resp, NULL, completion_code, entries, 1,
				      next_entry_handle, &new_size));
	assert(INPUT_ERROR == mctp_encode_get_routing_table_resp(
				      resp, &length, completion_code, NULL, 1,
				      next_entry_handle, &new_size));
	assert(INPUT_ERROR == mctp_encode_get_routing_table_resp(
				      resp, &length, completion_code, entries,
				      1, next_entry_handle, NULL));
	assert(GENERIC_ERROR == mctp_encode_get_routing_table_resp(
					resp, &temp_length, completion_code,
					entries, 1, next_entry_handle,
					&new_size));

	next_entry_handle = 0xFF;
	assert(INPUT_ERROR == mctp_encode_get_routing_table_resp(
				      NULL, &length, completion_code, entries,
				      1, next_entry_handle, &new_size));
	assert(INPUT_ERROR == mctp_encode_get_routing_table_resp(
				      resp, NULL, completion_code, entries, 1,
				      next_entry_handle, &new_size));
	assert(INPUT_ERROR == mctp_encode_get_routing_table_resp(
				      resp, &length, completion_code, NULL, 1,
				      next_entry_handle, &new_size));
	assert(INPUT_ERROR == mctp_encode_get_routing_table_resp(
				      resp, &length, completion_code, entries,
				      1, next_entry_handle, NULL));
	assert(GENERIC_ERROR == mctp_encode_get_routing_table_resp(
					resp, &temp_length, completion_code,
					entries, 1, next_entry_handle,
					&new_size));
}

static void test_encode_get_ver_support_resp()
{
	encode_decode_rc ret;
	uint8_t expected_instance_id = 0x01;
	size_t length = sizeof(struct mctp_ctrl_resp_get_mctp_ver_support);
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	uint8_t response_buffer
		[13]; // sizeof(mctp_get_ver_support_resp) + sizeof(single_version)
	struct mctp_ctrl_resp_get_mctp_ver_support *response =
		(struct mctp_ctrl_resp_get_mctp_ver_support *)(response_buffer);
	struct version_entry *vers;
	uint8_t number_of_entries = 2;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	vers = (struct version_entry *)malloc(2 *
					      (sizeof(struct version_entry)));
	vers[0].major = 2;
	vers[0].minor = 3;
	vers[0].update = 4;
	vers[0].alpha = 5;
	vers[1].major = 6;
	vers[1].minor = 7;
	vers[1].update = 8;
	vers[1].alpha = 9;
	struct mctp_msg *resp = (struct mctp_msg *)(response);

	ret = mctp_encode_get_ver_support_resp(resp, &length, rq_d_inst,
					       completion_code,
					       number_of_entries, vers);
	assert(ret == SUCCESS);
	assert(response->ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);
	assert(response->ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response->ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response->number_of_entries == number_of_entries);
	assert(response->version.major == vers[0].major);
	assert(response->version.minor == vers[0].minor);
	assert(response->version.update == vers[0].update);
	assert(response->version.alpha == vers[0].alpha);
	for (int i = 0; i < number_of_entries - 1; i++) {
		assert(response->versions[i].major == vers[i + 1].major);
		assert(response->versions[i].minor == vers[i + 1].minor);
		assert(response->versions[i].update == vers[i + 1].update);
		assert(response->versions[i].alpha == vers[i + 1].alpha);
	}
	free(vers);
}

static void test_negative_encode_get_ver_support_resp()
{
	encode_decode_rc ret;
	uint8_t expected_instance_id = 0x01;
	size_t temp_length = 0;
	size_t length = sizeof(struct mctp_ctrl_resp_get_mctp_ver_support);
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct version_entry vers;
	struct mctp_ctrl_resp_get_mctp_ver_support response;
	uint8_t number_of_entries = 1;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	vers.major = 2;
	vers.minor = 3;
	vers.update = 4;
	vers.alpha = 5;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	ret = mctp_encode_get_ver_support_resp(NULL, &length, rq_d_inst,
					       completion_code,
					       number_of_entries, &vers);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_get_ver_support_resp(resp, NULL, rq_d_inst,
					       completion_code,
					       number_of_entries, &vers);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_get_ver_support_resp(resp, &temp_length, rq_d_inst,
					       completion_code,
					       number_of_entries, &vers);
	assert(ret == GENERIC_ERROR);
	ret = mctp_encode_get_ver_support_resp(resp, &length, rq_d_inst,
					       completion_code,
					       number_of_entries, NULL);
	assert(ret == INPUT_ERROR);
}

static void test_encode_get_eid_resp()
{
	encode_decode_rc ret;
	struct mctp_ctrl_resp_get_eid response;
	size_t length = sizeof(struct mctp_ctrl_resp_get_eid);
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	mctp_eid_t eid = 10;
	uint8_t eid_type = 9;
	uint8_t medium_data = 8;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_get_eid_resp(resp, &length, rq_d_inst,
				       completion_code, eid, eid_type,
				       medium_data);
	assert(ret == SUCCESS);

	assert(response.ctrl_hdr.command_code == MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response.eid == eid);
	assert(response.eid_type == eid_type);
	assert(response.medium_data == medium_data);
}

static void test_negative_encode_get_eid_resp()
{
	encode_decode_rc ret;
	struct mctp_msg *response = NULL;
	size_t temp_length = 0;
	size_t length = sizeof(struct mctp_ctrl_resp_get_eid);
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	mctp_eid_t eid = 10;
	uint8_t eid_type = 9;
	uint8_t medium_data = 8;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	ret = mctp_encode_get_eid_resp(response, &length, rq_d_inst,
				       completion_code, eid, eid_type,
				       medium_data);
	assert(ret == INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_get_eid_resp(&response1, NULL, rq_d_inst,
				       completion_code, eid, eid_type,
				       medium_data);
	assert(ret == INPUT_ERROR);
	ret = mctp_encode_get_eid_resp(&response1, &temp_length, rq_d_inst,
				       completion_code, eid, eid_type,
				       medium_data);
	assert(ret == GENERIC_ERROR);
}

int main(int argc, char *argv[])
{
	test_encode_resolve_eid_resp();
	test_encode_allocate_eid_pool_resp();
	test_encode_set_eid_resp();
	test_encode_get_uuid_resp();
	test_encode_get_networkid_resp();
	test_encode_get_routing_table_resp();
	test_encode_get_ver_support_resp();
	test_encode_get_eid_resp();

	/*Negative test cases */
	test_negative_encode_resolve_eid_resp();
	test_negative_encode_allocate_eid_pool_resp();
	test_negative_encode_set_eid_resp();
	test_negative_encode_get_uuid_resp();
	test_negative_encode_get_networkid_resp();
	test_negative_encode_get_routing_table_resp();
	test_negative_encode_get_ver_support_resp();
	test_negative_encode_get_eid_resp();

	return EXIT_SUCCESS;
}