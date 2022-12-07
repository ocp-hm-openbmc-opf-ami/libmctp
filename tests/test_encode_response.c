#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp-encode-response.h"

static void test_encode_resolve_eid_resp()
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
	assert(ret == ENCODE_INPUT_ERROR);
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

static void test_encode_get_networkid_resp()
{
	encode_rc ret = false;
	struct mctp *mctp;
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
	ret = mctp_encode_get_networkid_resp(
		resp, sizeof(struct mctp_ctrl_get_networkid_resp),
		completion_code, &networkid);
	assert(ret == ENCODE_SUCCESS);
	assert(response.completion_code == MCTP_CTRL_CC_SUCCESS);
	assert(response.networkid.canonical.data1 == networkid.canonical.data1);
	assert(memcmp(response.networkid.raw, networkid.raw, sizeof(guid_t)) ==
	       0);
	mctp_destroy(mctp);
}

static void test_negative_encode_get_networkid_resp()
{
	encode_rc ret;
	struct mctp_msg response;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	guid_t networkid;

	ret = mctp_encode_get_networkid_resp(
		NULL, sizeof(struct mctp_ctrl_get_networkid_resp),
		completion_code, &networkid);
	assert(ret == ENCODE_INPUT_ERROR);
	ret = mctp_encode_get_networkid_resp(&response, 0, completion_code,
					     &networkid);
	assert(ret == ENCODE_GENERIC_ERROR);
	ret = mctp_encode_get_networkid_resp(
		&response, sizeof(struct mctp_ctrl_get_networkid_resp),
		completion_code, NULL);
	assert(ret == ENCODE_INPUT_ERROR);
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

	assert(ENCODE_SUCCESS ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 0, &new_size, next_entry_handle));

	next_entry_handle = 0x01;
	assert(ENCODE_SUCCESS ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 0, &new_size, next_entry_handle));
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

	assert(ENCODE_INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       NULL, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, &new_size, next_entry_handle));
	assert(ENCODE_INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       NULL, 1, &new_size, next_entry_handle));
	assert(ENCODE_INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, NULL, next_entry_handle));
	assert(ENCODE_GENERIC_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, 0, entries, 1, &new_size, next_entry_handle));

	next_entry_handle = 0xFF;
	assert(ENCODE_INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       NULL, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, &new_size, next_entry_handle));
	assert(ENCODE_INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       NULL, 1, &new_size, next_entry_handle));
	assert(ENCODE_INPUT_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, sizeof(struct mctp_ctrl_resp_get_routing_table),
		       entries, 1, NULL, next_entry_handle));
	assert(ENCODE_GENERIC_ERROR ==
	       mctp_encode_get_routing_table_resp(
		       resp, 0, entries, 1, &new_size, next_entry_handle));
}

static void test_encode_get_ver_support_resp()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t number_of_entries = 10;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_ctrl_resp_get_mctp_ver_support response;
	struct version_entry vers;
	vers.major = 2;
	vers.minor = 3;
	vers.update = 4;
	vers.alpha = 5;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		rq_d_inst, completion_code, number_of_entries, &vers);
	assert(ret == ENCODE_SUCCESS);
	assert(response.ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VERSION_SUPPORT);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response.number_of_entries == number_of_entries);
	assert(response.version.major == vers.major);
	assert(response.version.minor == vers.minor);
	assert(response.version.update == vers.update);
	assert(response.version.alpha == vers.alpha);
}

static void test_negative_encode_get_ver_support_resp()
{
	encode_rc ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t number_of_entries = 10;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct version_entry vers;
	struct mctp_ctrl_resp_get_mctp_ver_support response;
	vers.major = 2;
	vers.minor = 3;
	vers.update = 4;
	vers.alpha = 5;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);
	ret = mctp_encode_get_ver_support_resp(
		NULL, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		rq_d_inst, completion_code, number_of_entries, &vers);
	assert(ret == ENCODE_INPUT_ERROR);
	ret = mctp_encode_get_ver_support_resp(
		resp, 0, rq_d_inst, completion_code, number_of_entries, &vers);
	assert(ret == ENCODE_GENERIC_ERROR);
	ret = mctp_encode_get_ver_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_mctp_ver_support),
		rq_d_inst, completion_code, number_of_entries, NULL);
	assert(ret == ENCODE_INPUT_ERROR);
}

static void test_encode_get_eid_resp()
{
	encode_rc ret;
	struct mctp_ctrl_resp_get_eid response;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	mctp_eid_t eid = 10;
	uint8_t eid_type = 9;
	uint8_t medium_data = 8;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_get_eid_resp(resp,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       rq_d_inst, completion_code, eid,
				       eid_type, medium_data);
	assert(ret == ENCODE_SUCCESS);

	assert(response.ctrl_hdr.command_code == MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response.eid == eid);
	assert(response.eid_type == eid_type);
	assert(response.medium_data == medium_data);
}

static void test_negative_encode_get_eid_resp()
{
	encode_rc ret;
	struct mctp_msg *response = NULL;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	mctp_eid_t eid = 10;
	uint8_t eid_type = 9;
	uint8_t medium_data = 8;
	uint8_t completion_code = MCTP_CTRL_CC_SUCCESS;
	ret = mctp_encode_get_eid_resp(response,
				       sizeof(struct mctp_ctrl_resp_get_eid),
				       rq_d_inst, completion_code, eid,
				       eid_type, medium_data);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_get_eid_resp(&response1, 0, rq_d_inst,
				       completion_code, eid, eid_type,
				       medium_data);
	assert(ret == ENCODE_GENERIC_ERROR);
}

static void test_encode_get_vdm_support_resp()
{
	encode_rc ret;
	uint8_t vendor_id_set_selector = 9;
	uint8_t vendor_id_format = 8;
	uint16_t vendor_id_data_pcie = 9;
	uint8_t expected_instance_id = 0x01;
	struct mctp_ctrl_resp_get_vdm_support response;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *resp = (struct mctp_msg *)(&response);

	ret = mctp_encode_get_vdm_support_resp(
		resp, sizeof(struct mctp_ctrl_resp_get_vdm_support), rq_d_inst,
		vendor_id_set_selector, vendor_id_format, vendor_id_data_pcie);
	assert(ret == ENCODE_SUCCESS);
	assert(response.ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response.vendor_id_set_selector == vendor_id_set_selector);
	assert(response.vendor_id_format == vendor_id_format);
	assert(response.vendor_id_data_pcie == vendor_id_data_pcie);
}

static void test_negative_encode_get_vdm_support_resp()
{
	encode_rc ret;
	uint8_t vendor_id_set_selector = 9;
	uint8_t vendor_id_format = 8;
	uint16_t vendor_id_data_pcie = 9;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_msg *response = NULL;

	ret = mctp_encode_get_vdm_support_resp(
		response, sizeof(struct mctp_ctrl_resp_get_vdm_support),
		rq_d_inst, vendor_id_set_selector, vendor_id_format,
		vendor_id_data_pcie);
	assert(ret == ENCODE_INPUT_ERROR);
	struct mctp_msg response1;
	ret = mctp_encode_get_vdm_support_resp(&response1, 0, rq_d_inst,
					       vendor_id_set_selector,
					       vendor_id_format,
					       vendor_id_data_pcie);
	assert(ret == ENCODE_GENERIC_ERROR);
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
	test_encode_get_vdm_support_resp();

	/*Negative test cases */
	test_negative_encode_resolve_eid_resp();
	test_negative_encode_allocate_eid_pool_resp();
	test_negative_encode_set_eid_resp();
	test_negative_encode_get_uuid_resp();
	test_negative_encode_get_networkid_resp();
	test_negative_encode_get_routing_table_resp();
	test_negative_encode_get_ver_support_resp();
	test_negative_encode_get_eid_resp();
	test_negative_encode_get_vdm_support_resp();

	return EXIT_SUCCESS;
}