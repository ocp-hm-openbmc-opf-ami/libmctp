/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-cmds.h"
#include "libmctp.h"

#define COMPLETION_CODE 5

static void test_get_eid_encode()
{
	bool ret;
	uint8_t expected_instance_id = 0x01;
	uint8_t instance_id;
	uint8_t rq;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_ctrl_cmd_get_eid get_eid_cmd;

	ret = mctp_encode_ctrl_cmd_get_eid(&get_eid_cmd, rq_d_inst);
	assert(ret == true);
	assert(get_eid_cmd.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	assert(get_eid_cmd.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);

	instance_id = get_eid_cmd.ctrl_msg_hdr.rq_dgram_inst &
		      MCTP_CTRL_HDR_INSTANCE_ID_MASK;
	assert(expected_instance_id == instance_id);

	rq = get_eid_cmd.ctrl_msg_hdr.rq_dgram_inst &
	     MCTP_CTRL_HDR_FLAG_REQUEST;
	assert(rq == MCTP_CTRL_HDR_FLAG_REQUEST);
}

static void test_encode_ctrl_cmd_req_update_routing_info(void)
{
	struct get_routing_table_entry_with_address entries[1];
	/* Array to hold routing info update request*/
	uint8_t buf[256];
	struct mctp_ctrl_cmd_routing_info_update *req =
		(struct mctp_ctrl_cmd_routing_info_update *)buf;
	size_t new_size = 0;
	const size_t exp_new_size =
		sizeof(struct mctp_ctrl_cmd_routing_info_update) + 4;

	entries[0].routing_info.eid_range_size = 1;
	entries[0].routing_info.starting_eid = 9;
	entries[0].routing_info.entry_type = 2;
	entries[0].routing_info.phys_transport_binding_id = 1;
	entries[0].routing_info.phys_media_type_id = 4;
	entries[0].routing_info.phys_address_size = 1;
	entries[0].phys_address[0] = 0x12;

	assert(mctp_encode_ctrl_cmd_routing_information_update(
		req, 0xFF, entries, 1, &new_size));

	assert(new_size == exp_new_size);
	assert(req->count == 1);

	assert(!mctp_encode_ctrl_cmd_routing_information_update(
		NULL, 0xFF, entries, 1, &new_size));
	assert(!mctp_encode_ctrl_cmd_routing_information_update(req, 0xFF, NULL,
								1, &new_size));
}

static void test_encode_ctrl_cmd_rsp_get_routing_table(void)
{
	struct get_routing_table_entry_with_address entries[1];
	entries[0].routing_info.eid_range_size = 1;
	entries[0].routing_info.starting_eid = 9;
	entries[0].routing_info.entry_type = 2;
	entries[0].routing_info.phys_transport_binding_id = 1;
	entries[0].routing_info.phys_media_type_id = 4;
	entries[0].routing_info.phys_address_size = 1;
	entries[0].phys_address[0] = 0x12;

	struct mctp_ctrl_resp_get_routing_table resp;

	size_t new_size = 0;
	uint8_t next_entry_handle = 0x01;
	assert(mctp_encode_ctrl_cmd_get_routing_table_resp(
		&resp, entries, 1, &new_size, next_entry_handle));
	next_entry_handle = 0xFF;
	assert(mctp_encode_ctrl_cmd_get_routing_table_resp(
		&resp, entries, 1, &new_size, next_entry_handle));

	size_t exp_new_size =
		sizeof(struct mctp_ctrl_resp_get_routing_table) +
		sizeof(struct get_routing_table_entry_with_address) +
		entries[0].routing_info.phys_address_size -
		sizeof(entries[0].phys_address);
	assert(new_size == exp_new_size);
	assert(resp.completion_code == MCTP_CTRL_CC_SUCCESS);
	assert(resp.next_entry_handle == 0xFF);
	assert(resp.number_of_entries == 0x01);

	next_entry_handle = 0xFF;

	assert(!mctp_encode_ctrl_cmd_get_routing_table_resp(
		NULL, entries, 1, &new_size, next_entry_handle));
	assert(!mctp_encode_ctrl_cmd_get_routing_table_resp(
		&resp, NULL, 1, &new_size, next_entry_handle));
	assert(!mctp_encode_ctrl_cmd_get_routing_table_resp(
		&resp, entries, 1, NULL, next_entry_handle));
	assert(mctp_encode_ctrl_cmd_get_routing_table_resp(
		&resp, entries, 0, &new_size, next_entry_handle));

	next_entry_handle = 0x01;

	assert(!mctp_encode_ctrl_cmd_get_routing_table_resp(
		NULL, entries, 1, &new_size, next_entry_handle));
	assert(!mctp_encode_ctrl_cmd_get_routing_table_resp(
		&resp, NULL, 1, &new_size, next_entry_handle));
	assert(!mctp_encode_ctrl_cmd_get_routing_table_resp(
		&resp, entries, 1, NULL, next_entry_handle));
	assert(mctp_encode_ctrl_cmd_get_routing_table_resp(
		&resp, entries, 0, &new_size, next_entry_handle));
}

static void test_decode_ctrl_cmd_resolve_eid_req()
{
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

	assert(mctp_decode_ctrl_cmd_resolve_eid_req(&cmd_resolve_eid, &ctrl_hdr,
						    &target_eid));
	assert(ctrl_hdr.command_code ==
	       cmd_resolve_eid.ctrl_msg_hdr.command_code);
	assert(ctrl_hdr.rq_dgram_inst ==
	       cmd_resolve_eid.ctrl_msg_hdr.rq_dgram_inst);
	assert(ctrl_hdr.ic_msg_type ==
	       cmd_resolve_eid.ctrl_msg_hdr.ic_msg_type);
	assert(target_eid == cmd_resolve_eid.target_eid);
}

static void test_decode_ctrl_cmd_resolve_eid_resp()
{
	bool ret;
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
	ret = mctp_decode_ctrl_cmd_resolve_eid_resp(response,
						    sizeof(packed_packet),
						    &ctrl_hdr, &completion_code,
						    &bridge_eid, &address);
	assert(ret == true);
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

static void test_encode_ctrl_cmd_resolve_eid_req()
{
	const uint8_t target_eid = 9;
	const uint8_t instance_id = 0x01;
	struct mctp_ctrl_cmd_resolve_eid_req cmd_resolve_eid;

	assert(mctp_encode_ctrl_cmd_resolve_eid_req(
		&cmd_resolve_eid, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		target_eid));

	assert(cmd_resolve_eid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID);
	assert(cmd_resolve_eid.ctrl_msg_hdr.rq_dgram_inst ==
	       (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(cmd_resolve_eid.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);

	assert(cmd_resolve_eid.target_eid == target_eid);
}

static void test_encode_ctrl_cmd_resolve_uuid_req(void)
{
	bool ret;

	/* 16 byte UUID */
	char sample_uuid[16] = "61a3";

	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	guid_t test_uuid;

	/*doing memcpy of string literal*/
	memcpy(&test_uuid.raw, sample_uuid, sizeof(guid_t));

	struct mctp_ctrl_cmd_resolve_uuid_req cmd_res_uuid;

	ret = mctp_encode_ctrl_cmd_resolve_uuid_req(&cmd_res_uuid, rq_d_inst,
						    &test_uuid, 0x00);

	assert(ret == true);
	assert(cmd_res_uuid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_RESOLVE_UUID);
	assert(cmd_res_uuid.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(cmd_res_uuid.ctrl_msg_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);

	assert(memcmp(cmd_res_uuid.req_uuid.raw, test_uuid.raw,
		      sizeof(guid_t)) == 0);
	assert(cmd_res_uuid.entry_handle == 0x00);
}

static void test_negation_encode_ctrl_cmd_resolve_uuid_req(void)
{
	bool ret;

	/* UUID is in RFC4122 format. Ex: 61a3 */
	char sample_uuid[16] = "61a3";
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	guid_t test_uuid;

	/*doing memcpy of string literal*/
	memcpy(&test_uuid.raw, sample_uuid, sizeof(guid_t));

	ret = mctp_encode_ctrl_cmd_resolve_uuid_req(NULL, rq_d_inst, &test_uuid,
						    0x00);
	assert(ret == false);
}

void test_encode_ctrl_cmd_query_hop(void)
{
	struct mctp_ctrl_cmd_query_hop_req cmd_query_hop;
	uint8_t sample_eid = 8;
	uint8_t instance_id = 0x01;

	/* Initialise with wrong value */
	cmd_query_hop.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	cmd_query_hop.ctrl_msg_hdr.rq_dgram_inst = 0x00;
	cmd_query_hop.ctrl_msg_hdr.ic_msg_type = 0x01;
	cmd_query_hop.target_eid = sample_eid + 1;
	cmd_query_hop.mctp_ctrl_msg_type = 0x01;

	assert(mctp_encode_ctrl_cmd_query_hop_req(
		&cmd_query_hop, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		sample_eid, MCTP_CTRL_HDR_MSG_TYPE));

	assert(cmd_query_hop.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_QUERY_HOP);

	assert(cmd_query_hop.ctrl_msg_hdr.rq_dgram_inst ==
	       (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));

	assert(cmd_query_hop.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);

	assert(cmd_query_hop.target_eid == sample_eid);
	assert(cmd_query_hop.mctp_ctrl_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
}

static void test_mctp_encode_ctrl_cmd_resolve_eid_resp()
{
	bool ret;
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

	ret = mctp_encode_ctrl_cmd_resolve_eid_resp(response, rq_d_inst,
						    bridge_eid, &address);
	assert(ret == true);
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

static void test_mctp_encode_ctrl_cmd_get_network_id_resp(void)
{
	bool rc = false;
	struct mctp *mctp;
	mctp = mctp_init();
	guid_t networkid;
	guid_t retrieved_networkid;
	networkid.canonical.data1 = 10;
	struct mctp_ctrl_get_networkid_resp response;

	rc = mctp_set_networkid(mctp, &networkid);
	assert(rc);

	rc = mctp_get_networkid(mctp, &retrieved_networkid);
	assert(rc);
	assert(networkid.canonical.data1 ==
	       retrieved_networkid.canonical.data1);

	bool ret = false;
	ret = mctp_encode_ctrl_cmd_get_network_id_resp(&response, &networkid);
	assert(ret);
	assert(response.completion_code == MCTP_CTRL_CC_SUCCESS);
	assert(response.networkid.canonical.data1 == networkid.canonical.data1);

	mctp_destroy(mctp);
}

static void test_decode_ctrl_cmd_query_hop_resp(void)
{
	bool ret = false;
	struct mctp_ctrl_cmd_query_hop_resp cmd_query_hop_resp;
	struct mctp_ctrl_msg_hdr hdr;
	cmd_query_hop_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
	cmd_query_hop_resp.next_bridge_eid = 10;
	cmd_query_hop_resp.mctp_ctrl_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	cmd_query_hop_resp.max_incoming_size = 8;
	cmd_query_hop_resp.max_outgoing_size = 8;
	cmd_query_hop_resp.ctrl_msg_hdr.ic_msg_type = 0x00;
	cmd_query_hop_resp.ctrl_msg_hdr.rq_dgram_inst = 0x00;
	cmd_query_hop_resp.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_QUERY_HOP;

	uint8_t completion_code;
	uint8_t next_bridge_eid;
	uint8_t mctp_ctrl_msg_type;
	uint16_t max_incoming_size;
	uint16_t max_outgoing_size;

	ret = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, sizeof(cmd_query_hop_resp), &hdr,
		&completion_code, &next_bridge_eid, &mctp_ctrl_msg_type,
		&max_incoming_size, &max_outgoing_size);

	assert(ret);
	assert(memcmp(&cmd_query_hop_resp.ctrl_msg_hdr, &hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
	assert(completion_code == cmd_query_hop_resp.completion_code);
	assert(next_bridge_eid == cmd_query_hop_resp.next_bridge_eid);
	assert(mctp_ctrl_msg_type == cmd_query_hop_resp.mctp_ctrl_msg_type);
	assert(max_incoming_size == cmd_query_hop_resp.max_incoming_size);
	assert(max_outgoing_size == cmd_query_hop_resp.max_outgoing_size);
	assert(hdr.ic_msg_type == cmd_query_hop_resp.ctrl_msg_hdr.ic_msg_type);
	assert(hdr.rq_dgram_inst ==
	       cmd_query_hop_resp.ctrl_msg_hdr.rq_dgram_inst);
}

static void test_decode_ctrl_cmd_query_hop_req(void)
{
	struct mctp_ctrl_cmd_query_hop_req cmd_query_hop;
	struct mctp_ctrl_msg_hdr hdr;
	cmd_query_hop.target_eid = 8;
	cmd_query_hop.mctp_ctrl_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	cmd_query_hop.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_QUERY_HOP;
	uint8_t sample_eid;
	uint8_t msg_type;

	assert(mctp_decode_ctrl_cmd_query_hop_req(&cmd_query_hop,
						  sizeof(cmd_query_hop), &hdr,
						  &sample_eid, &msg_type));
	assert(memcmp(&cmd_query_hop.ctrl_msg_hdr, &hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
	assert(sample_eid == cmd_query_hop.target_eid);
	assert(msg_type == cmd_query_hop.mctp_ctrl_msg_type);
}

/*Negative Test cases for the commands*/

static void test_negation_encode_ctrl_cmd_resolve_eid_req()
{
	bool ret;
	struct mctp_ctrl_cmd_resolve_eid_req *cmd_resolve_eid = NULL;
	const uint8_t target_eid = 9;
	const uint8_t instance_id = 0x01;

	ret = mctp_encode_ctrl_cmd_resolve_eid_req(
		cmd_resolve_eid, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		target_eid);

	assert(ret == false);
}

static void test_negative_decode_ctrl_cmd_resolve_eid_req()
{
	bool ret;
	struct mctp_ctrl_cmd_resolve_eid_req cmd_resolve_eid;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	uint8_t target_eid;
	cmd_resolve_eid.ctrl_msg_hdr.command_code =
		MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	ret = mctp_decode_ctrl_cmd_resolve_eid_req(NULL, &ctrl_hdr,
						   &target_eid);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_resolve_eid_req(&cmd_resolve_eid, NULL,
						   &target_eid);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_resolve_eid_req(&cmd_resolve_eid, &ctrl_hdr,
						   NULL);
	assert(ret == false);
	cmd_resolve_eid.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_ctrl_cmd_resolve_eid_req(&cmd_resolve_eid, &ctrl_hdr,
						   &target_eid);
	assert(ret == false);
}

static void test_negative_decode_ctrl_cmd_resolve_eid_resp()
{
	bool ret;
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
	response->completion_code = MCTP_CTRL_CC_SUCCESS;
	response->ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_ENDPOINT_ID;
	ret = mctp_decode_ctrl_cmd_resolve_eid_resp(NULL, sizeof(packed_packet),
						    &ctrl_hdr, &completion_code,
						    &bridge_eid, &address);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_resolve_eid_resp(response, 0, &ctrl_hdr,
						    &completion_code,
						    &bridge_eid, &address);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_resolve_eid_resp(response,
						    sizeof(packed_packet), NULL,
						    &completion_code,
						    &bridge_eid, &address);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_resolve_eid_resp(response,
						    sizeof(packed_packet),
						    &ctrl_hdr, NULL,
						    &bridge_eid, &address);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_resolve_eid_resp(response,
						    sizeof(packed_packet),
						    &ctrl_hdr, &completion_code,
						    NULL, &address);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_resolve_eid_resp(response,
						    sizeof(packed_packet),
						    &ctrl_hdr, &completion_code,
						    &bridge_eid, NULL);
	assert(ret == false);
	response->completion_code = MCTP_CTRL_CC_ERROR;
	ret = mctp_decode_ctrl_cmd_resolve_eid_resp(response,
						    sizeof(packed_packet),
						    &ctrl_hdr, &completion_code,
						    &bridge_eid, &address);
	assert(ret == false);
	response->ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_ctrl_cmd_resolve_eid_resp(response,
						    sizeof(packed_packet),
						    &ctrl_hdr, &completion_code,
						    &bridge_eid, &address);
	assert(ret == false);
}

static void test_negative_encode_ctrl_cmd_query_hop()
{
	uint8_t sample_eid = 8;
	uint8_t instance_id = 0x01;
	struct mctp_ctrl_cmd_query_hop_req *query_hop = NULL;
	bool rc = true;
	rc = mctp_encode_ctrl_cmd_query_hop_req(
		query_hop, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		sample_eid, MCTP_CTRL_HDR_MSG_TYPE);
	assert(!rc);
}

static void test_negation_encode_ctrl_cmd_resolve_eid_resp()
{
	bool ret;
	struct mctp_ctrl_cmd_resolve_eid_resp response;
	uint8_t phy_address[] = { 10, 12, 13 };
	struct variable_field address;
	address.data = phy_address;
	address.data_size = sizeof(phy_address);
	const uint8_t instance_id = 0x01;
	const uint8_t bridge_eid = 10;
	ret = mctp_encode_ctrl_cmd_resolve_eid_resp(
		NULL, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST), bridge_eid,
		&address);
	assert(ret == false);
	ret = mctp_encode_ctrl_cmd_resolve_eid_resp(
		&response, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		bridge_eid, NULL);
	assert(ret == false);
}

static void test_allocate_eid_pool_encode_req()
{
	bool ret;
	const uint8_t first_eid = 9;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_req_op operation = allocate_eids;
	struct mctp_ctrl_cmd_allocate_eids_req cmd_allocate_eid;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;

	ret = mctp_encode_ctrl_cmd_allocate_endpoint_id_req(
		&cmd_allocate_eid, rq_d_inst, operation, eid_pool_size,
		first_eid);
	assert(ret == true);
	assert(cmd_allocate_eid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	assert(cmd_allocate_eid.ctrl_msg_hdr.rq_dgram_inst == rq_d_inst);
	assert(cmd_allocate_eid.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);

	assert(cmd_allocate_eid.operation == operation);

	assert(cmd_allocate_eid.eid_pool_size == eid_pool_size);
	assert(cmd_allocate_eid.first_eid == first_eid);
}

static void test_allocate_eid_pool_encode_resp()
{
	bool ret;
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

	ret = mctp_encode_ctrl_cmd_allocate_endpoint_id_resp(
		&response, &ctrl_hdr, op, eid_pool_size, first_eid);

	assert(ret == true);

	assert(response.ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(response.operation == op);
	assert(response.eid_pool_size == eid_pool_size);
	assert(response.first_eid == first_eid);
}

static void test_negation_allocate_eid_pool_encode_req()
{
	bool ret;
	uint8_t sample_eid = 10;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_req_op operation = allocate_eids;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_ctrl_cmd_allocate_eids_req *cmd_allocate_eid = NULL;

	ret = mctp_encode_ctrl_cmd_allocate_endpoint_id_req(
		cmd_allocate_eid, rq_d_inst, operation, eid_pool_size,
		sample_eid);
	assert(ret == false);
}

static void test_negation_allocate_eid_pool_encode_resp()
{
	bool ret;
	struct mctp_ctrl_cmd_allocate_eids_resp *response = NULL;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	ctrl_hdr.rq_dgram_inst = rq_d_inst;
	ctrl_hdr.command_code = MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS;
	mctp_ctrl_cmd_allocate_eids_resp_op op = allocation_accepted;
	uint8_t eid_pool_size = 10;
	uint8_t first_eid = 9;

	ret = mctp_encode_ctrl_cmd_allocate_endpoint_id_resp(
		response, &ctrl_hdr, op, eid_pool_size, first_eid);
	assert(ret == false);
}

static void test_allocate_eid_pool_decode_req()
{
	int ret;
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

	ret = mctp_decode_ctrl_cmd_allocate_endpoint_id_req(
		&request, &ic_msg_type, &rq_dgram_inst, &command_code, &op,
		&eid_pool_size, &first_eid);

	assert(ret == true);
	assert(ic_msg_type == request.ctrl_msg_hdr.ic_msg_type);
	assert(rq_dgram_inst == request.ctrl_msg_hdr.rq_dgram_inst);
	assert(command_code == request.ctrl_msg_hdr.command_code);
	assert(op == request.operation);
	assert(eid_pool_size == request.eid_pool_size);
	assert(first_eid == request.first_eid);
}

static void test_negation_allocate_eid_pool_decode_req()
{
	int ret;
	struct mctp_ctrl_cmd_allocate_eids_req *request = NULL;

	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
	mctp_ctrl_cmd_allocate_eids_req_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;

	ret = mctp_decode_ctrl_cmd_allocate_endpoint_id_req(
		request, &ic_msg_type, &rq_dgram_inst, &command_code, &op,
		&eid_pool_size, &first_eid);

	assert(ret == false);
}

static void test_allocate_eid_pool_decode_resp()
{
	int ret;
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

	ret = mctp_decode_ctrl_cmd_allocate_endpoint_id_resp(
		&response, &ic_msg_type, &rq_dgram_inst, &command_code, &cc,
		&op, &eid_pool_size, &first_eid);

	assert(ret == true);
	assert(ic_msg_type == response.ctrl_hdr.ic_msg_type);
	assert(rq_dgram_inst == response.ctrl_hdr.rq_dgram_inst);
	assert(command_code == response.ctrl_hdr.command_code);
	assert(cc == response.completion_code);
	assert(op == response.operation);
	assert(eid_pool_size == response.eid_pool_size);
	assert(first_eid == response.first_eid);
}

static void test_negation_allocate_eid_pool_decode_resp()
{
	int ret;
	struct mctp_ctrl_cmd_allocate_eids_resp *response = NULL;

	uint8_t ic_msg_type;
	uint8_t rq_dgram_inst;
	uint8_t command_code;
	uint8_t cc;
	mctp_ctrl_cmd_allocate_eids_resp_op op;
	uint8_t eid_pool_size;
	uint8_t first_eid;

	ret = mctp_decode_ctrl_cmd_allocate_endpoint_id_resp(
		response, &ic_msg_type, &rq_dgram_inst, &command_code, &cc, &op,
		&eid_pool_size, &first_eid);

	assert(ret == false);
}

void test_check_encode_cc_only_response()
{
	struct mctp_ctrl_resp_completion_code response;
	assert((encode_cc_only_response(COMPLETION_CODE, &response)));
	assert(response.completion_code == COMPLETION_CODE);
}

void test_negative_encode_cc_only_response()
{
	struct mctp_ctrl_resp_completion_code *response = NULL;
	assert(!(encode_cc_only_response(COMPLETION_CODE, response)));
}

static void test_encode_ctrl_cmd_get_networkid_req(void)
{
	struct mctp_ctrl_cmd_get_networkid_req cmd_get_networkid;
	uint8_t instance_id = 0x01;

	assert(mctp_encode_ctrl_cmd_get_networkid_req(
		&cmd_get_networkid,
		(instance_id | MCTP_CTRL_HDR_FLAG_REQUEST)));

	assert(cmd_get_networkid.ctrl_msg_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_NETWORK_ID);
	assert(cmd_get_networkid.ctrl_msg_hdr.rq_dgram_inst ==
	       (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));
	assert(cmd_get_networkid.ctrl_msg_hdr.ic_msg_type ==
	       MCTP_CTRL_HDR_MSG_TYPE);
}

static void test_negation_encode_ctrl_cmd_get_networkid_req()
{
	bool ret = true;
	uint8_t instance_id = 0x01;

	ret = mctp_encode_ctrl_cmd_get_networkid_req(
		NULL, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST));

	assert(!ret);
}

static void test_decode_ctrl_cmd_network_id_req(void)
{
	bool ret = true;
	struct mctp_ctrl_cmd_get_networkid_req cmd_network_id;
	struct mctp_ctrl_msg_hdr hdr;
	cmd_network_id.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	cmd_network_id.ctrl_msg_hdr.rq_dgram_inst = 10;
	cmd_network_id.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_NETWORK_ID;

	ret = mctp_decode_ctrl_cmd_network_id_req(&cmd_network_id,
						  sizeof(cmd_network_id), &hdr);
	assert(ret);
	assert(memcmp(&cmd_network_id.ctrl_msg_hdr, &hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
}

static void test_decode_ctrl_cmd_network_id_resp(void)
{
	bool ret = true;
	struct mctp_ctrl_get_networkid_resp cmd_network_id_resp;
	struct mctp_ctrl_msg_hdr hdr;
	guid_t network_id;

	network_id.canonical.data1 = 10;
	cmd_network_id_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
	cmd_network_id_resp.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	cmd_network_id_resp.ctrl_hdr.rq_dgram_inst = 10;
	cmd_network_id_resp.ctrl_hdr.command_code =
		MCTP_CTRL_CMD_GET_NETWORK_ID;

	uint8_t completion_code;
	ret = mctp_decode_ctrl_cmd_network_id_resp(&cmd_network_id_resp,
						   sizeof(cmd_network_id_resp),
						   &hdr, &completion_code,
						   &network_id);
	assert(ret);
	assert(memcmp(&cmd_network_id_resp.ctrl_hdr, &hdr,
		      sizeof(struct mctp_ctrl_msg_hdr)) == 0);
	assert(completion_code == cmd_network_id_resp.completion_code);
	assert(network_id.canonical.data1 ==
	       cmd_network_id_resp.networkid.canonical.data1);
}

static void test_negative_decode_ctrl_cmd_network_id_req(void)
{
	struct mctp_ctrl_cmd_get_networkid_req cmd_network_id;
	struct mctp_ctrl_msg_hdr hdr;
	cmd_network_id.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	cmd_network_id.ctrl_msg_hdr.rq_dgram_inst = 10;
	cmd_network_id.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_GET_NETWORK_ID;
	bool ret = true;

	ret = mctp_decode_ctrl_cmd_network_id_req(NULL, sizeof(cmd_network_id),
						  &hdr);
	assert(!ret);
	ret = mctp_decode_ctrl_cmd_network_id_req(&cmd_network_id, 8, &hdr);
	assert(!ret);
	ret = mctp_decode_ctrl_cmd_network_id_req(&cmd_network_id,
						  sizeof(cmd_network_id), NULL);
	assert(!ret);
	cmd_network_id.ctrl_msg_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_ctrl_cmd_network_id_req(&cmd_network_id,
						  sizeof(cmd_network_id), &hdr);
	assert(!ret);
}

static void test_negative_decode_ctrl_cmd_network_id_resp(void)
{
	bool ret = true;
	struct mctp_ctrl_get_networkid_resp cmd_network_id_resp;
	struct mctp_ctrl_msg_hdr hdr;
	guid_t network_id;

	network_id.canonical.data1 = 10;
	cmd_network_id_resp.completion_code = MCTP_CTRL_CC_ERROR;
	cmd_network_id_resp.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	cmd_network_id_resp.ctrl_hdr.rq_dgram_inst = 10;
	cmd_network_id_resp.ctrl_hdr.command_code =
		MCTP_CTRL_CMD_GET_NETWORK_ID;
	uint8_t completion_code;
	ret = mctp_decode_ctrl_cmd_network_id_resp(NULL,
						   sizeof(cmd_network_id_resp),
						   &hdr, &completion_code,
						   &network_id);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_network_id_resp(
		&cmd_network_id_resp, 10, &hdr, &completion_code, &network_id);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_network_id_resp(&cmd_network_id_resp,
						   sizeof(cmd_network_id_resp),
						   NULL, &completion_code,
						   &network_id);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_network_id_resp(&cmd_network_id_resp,
						   sizeof(cmd_network_id_resp),
						   &hdr, NULL, &network_id);
	assert(ret == false);
	ret = mctp_decode_ctrl_cmd_network_id_resp(&cmd_network_id_resp,
						   sizeof(cmd_network_id_resp),
						   &hdr, &completion_code,
						   NULL);
	assert(!ret);
	cmd_network_id_resp.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESOLVE_UUID;
	ret = mctp_decode_ctrl_cmd_network_id_resp(&cmd_network_id_resp,
						   sizeof(cmd_network_id_resp),
						   &hdr, &completion_code,
						   &network_id);
	assert(!ret);
}

static void test_negative_decode_ctrl_cmd_query_hop_resp()
{
	bool rc = true;
	struct mctp_ctrl_cmd_query_hop_resp cmd_query_hop_resp;
	struct mctp_ctrl_msg_hdr hdr;
	uint8_t completion_code;
	uint8_t next_bridge_eid;
	uint8_t mctp_ctrl_msg_type;
	uint16_t max_incoming_size;
	uint16_t max_outgoing_size;

	cmd_query_hop_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
	cmd_query_hop_resp.next_bridge_eid = 10;
	cmd_query_hop_resp.mctp_ctrl_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	cmd_query_hop_resp.max_incoming_size = 8;
	cmd_query_hop_resp.max_outgoing_size = 8;

	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		NULL, sizeof(cmd_query_hop_resp), &hdr, &completion_code,
		&next_bridge_eid, &mctp_ctrl_msg_type, &max_incoming_size,
		&max_outgoing_size);
	assert(!rc);

	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, 0, &hdr, &completion_code,
		&next_bridge_eid, &mctp_ctrl_msg_type, &max_incoming_size,
		&max_outgoing_size);
	assert(!rc);

	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, sizeof(cmd_query_hop_resp), NULL,
		&completion_code, &next_bridge_eid, &mctp_ctrl_msg_type,
		&max_incoming_size, &max_outgoing_size);
	assert(!rc);

	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, sizeof(cmd_query_hop_resp), &hdr, NULL,
		&next_bridge_eid, &mctp_ctrl_msg_type, &max_incoming_size,
		&max_outgoing_size);
	assert(!rc);

	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, sizeof(cmd_query_hop_resp), &hdr,
		&completion_code, NULL, &mctp_ctrl_msg_type, &max_incoming_size,
		&max_outgoing_size);
	assert(!rc);

	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, sizeof(cmd_query_hop_resp), &hdr,
		&completion_code, &next_bridge_eid, NULL, &max_incoming_size,
		&max_outgoing_size);
	assert(!rc);

	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, sizeof(cmd_query_hop_resp), &hdr,
		&completion_code, &next_bridge_eid, &mctp_ctrl_msg_type, NULL,
		&max_outgoing_size);
	assert(!rc);

	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, sizeof(cmd_query_hop_resp), &hdr,
		&completion_code, &next_bridge_eid, &mctp_ctrl_msg_type,
		&max_incoming_size, NULL);
	assert(!rc);

	cmd_query_hop_resp.completion_code = MCTP_CTRL_CC_ERROR;
	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, sizeof(cmd_query_hop_resp), &hdr,
		&completion_code, &next_bridge_eid, &mctp_ctrl_msg_type,
		&max_incoming_size, &max_outgoing_size);
	assert(!rc);

	cmd_query_hop_resp.mctp_ctrl_msg_type = MCTP_CTRL_CMD_RESERVED;
	rc = mctp_decode_ctrl_cmd_get_query_hop_resp(
		&cmd_query_hop_resp, sizeof(cmd_query_hop_resp), &hdr,
		&completion_code, &next_bridge_eid, &mctp_ctrl_msg_type,
		&max_incoming_size, &max_outgoing_size);
	assert(!rc);
}

static void test_negative_decode_ctrl_cmd_query_hop_req()
{
	bool ret = true;
	struct mctp_ctrl_cmd_query_hop_req query_hop;
	struct mctp_ctrl_msg_hdr hdr;
	query_hop.target_eid = 8;
	query_hop.mctp_ctrl_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t sample_eid;
	uint8_t msg_type;
	ret = mctp_decode_ctrl_cmd_query_hop_req(NULL, sizeof(query_hop), &hdr,
						 &sample_eid, &msg_type);
	assert(!ret);

	ret = mctp_decode_ctrl_cmd_query_hop_req(&query_hop, 0, &hdr,
						 &sample_eid, &msg_type);
	assert(!ret);

	ret = mctp_decode_ctrl_cmd_query_hop_req(&query_hop, sizeof(query_hop),
						 NULL, &sample_eid, &msg_type);
	assert(!ret);

	ret = mctp_decode_ctrl_cmd_query_hop_req(&query_hop, sizeof(query_hop),
						 &hdr, NULL, &msg_type);
	assert(!ret);

	ret = mctp_decode_ctrl_cmd_query_hop_req(&query_hop, sizeof(query_hop),
						 &hdr, &sample_eid, NULL);
	assert(!ret);

	query_hop.mctp_ctrl_msg_type = MCTP_CTRL_CMD_RESERVED;
	ret = mctp_decode_ctrl_cmd_query_hop_req(&query_hop, sizeof(query_hop),
						 &hdr, &sample_eid, &msg_type);
	assert(!ret);
}

static void test_get_uuid_encode_resp()
{
	bool ret;
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

	ret = mctp_encode_ctrl_cmd_get_uuid_resp(&response, &ctrl_hdr,
						 &test_uuid);

	assert(ret == true);

	assert(response.ctrl_hdr.command_code ==
	       MCTP_CTRL_CMD_GET_ENDPOINT_UUID);
	assert(response.ctrl_hdr.rq_dgram_inst == rq_d_inst);
	assert(response.ctrl_hdr.ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE);
	assert(memcmp(response.uuid.raw, test_uuid.raw, sizeof(guid_t)) == 0);
}

static void test_negation_get_uuid_encode_resp()
{
	bool ret;
	struct mctp_ctrl_resp_get_uuid *response = NULL;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
	ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	uint8_t expected_instance_id = 0x01;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	ctrl_hdr.rq_dgram_inst = rq_d_inst;
	ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_UUID;
	guid_t test_uuid;

	ret = mctp_encode_ctrl_cmd_get_uuid_resp(response, &ctrl_hdr,
						 &test_uuid);
	assert(ret == false);
	struct mctp_ctrl_resp_get_uuid response1;
	ret = mctp_encode_ctrl_cmd_get_uuid_resp(&response1, NULL, &test_uuid);
	assert(ret == false);
	ret = mctp_encode_ctrl_cmd_get_uuid_resp(&response1, &ctrl_hdr, NULL);
	assert(ret == false);
}

int main(int argc, char *argv[])
{
	test_get_eid_encode();
	test_encode_ctrl_cmd_req_update_routing_info();
	test_encode_ctrl_cmd_rsp_get_routing_table();
	test_decode_ctrl_cmd_resolve_eid_req();
	test_decode_ctrl_cmd_resolve_eid_resp();
	test_encode_ctrl_cmd_resolve_eid_req();
	test_encode_ctrl_cmd_resolve_uuid_req();
	test_encode_ctrl_cmd_query_hop();
	test_mctp_encode_ctrl_cmd_resolve_eid_resp();
	test_check_encode_cc_only_response();
	test_allocate_eid_pool_encode_req();
	test_allocate_eid_pool_encode_resp();
	test_allocate_eid_pool_decode_req();
	test_allocate_eid_pool_decode_resp();
	test_mctp_encode_ctrl_cmd_get_network_id_resp();
	test_encode_ctrl_cmd_get_networkid_req();
	test_decode_ctrl_cmd_network_id_req();
	test_decode_ctrl_cmd_network_id_resp();
	test_decode_ctrl_cmd_query_hop_resp();
	test_decode_ctrl_cmd_query_hop_req();
	test_get_uuid_encode_resp();

	/*Negative test cases */
	test_negative_decode_ctrl_cmd_resolve_eid_req();
	test_negative_decode_ctrl_cmd_resolve_eid_resp();
	test_negation_encode_ctrl_cmd_resolve_eid_req();
	test_negation_encode_ctrl_cmd_resolve_uuid_req();
	test_negation_allocate_eid_pool_encode_req();
	test_negation_allocate_eid_pool_encode_resp();
	test_negation_allocate_eid_pool_decode_req();
	test_negation_allocate_eid_pool_decode_resp();
	test_negative_encode_ctrl_cmd_query_hop();
	test_negation_encode_ctrl_cmd_resolve_eid_resp();
	test_negation_encode_ctrl_cmd_get_networkid_req();
	test_negative_decode_ctrl_cmd_network_id_req();
	test_negative_decode_ctrl_cmd_network_id_resp();
	test_negative_decode_ctrl_cmd_query_hop_resp();
	test_negative_decode_ctrl_cmd_query_hop_req();
	test_negative_encode_cc_only_response();
	test_negation_get_uuid_encode_resp();
	return EXIT_SUCCESS;
}
