/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "libmctp-cmds.h"
#include "core.c"

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
	assert(mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, entries, 1,
							  &new_size));

	size_t exp_new_size =
		sizeof(struct mctp_ctrl_resp_get_routing_table) +
		sizeof(struct get_routing_table_entry_with_address) +
		entries[0].routing_info.phys_address_size -
		sizeof(entries[0].phys_address);
	assert(new_size == exp_new_size);
	assert(resp.completion_code == MCTP_CTRL_CC_SUCCESS);
	assert(resp.next_entry_handle == 0xFF);
	assert(resp.number_of_entries == 0x01);

	assert(!mctp_encode_ctrl_cmd_rsp_get_routing_table(NULL, entries, 1,
							   &new_size));
	assert(!mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, NULL, 1,
							   &new_size));
	assert(!mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, entries, 1,
							   NULL));
	assert(mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, entries, 0,
							  &new_size));
}

void test_encode_ctrl_cmd_query_hop(void)
{
	struct mctp_ctrl_cmd_query_hop cmd_query_hop;
	uint8_t sample_eid = 8;
	uint8_t instance_id = 0x01;
	assert(mctp_encode_ctrl_cmd_query_hop(
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

/*Negative Test cases for the commands*/

static void test_negative_encode_ctrl_cmd_query_hop()
{
	uint8_t sample_eid = 8;
	uint8_t instance_id = 0x01;
	struct mctp_ctrl_cmd_query_hop *query_hop = NULL;
	bool rc = true;
	rc = mctp_encode_ctrl_cmd_query_hop(
		query_hop, (instance_id | MCTP_CTRL_HDR_FLAG_REQUEST),
		sample_eid, MCTP_CTRL_HDR_MSG_TYPE);
	assert(!rc);
}

static void test_allocate_eid_pool_encode()
{
	bool ret;
	const uint8_t first_eid = 9;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_op operation = allocate_eids;
	struct mctp_ctrl_cmd_allocate_eids cmd_allocate_eid;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;

	ret = mctp_encode_ctrl_cmd_allocate_eids(&cmd_allocate_eid, rq_d_inst,
						 operation, eid_pool_size,
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

static void test_negation_allocate_eid_pool_encode()
{
	bool ret;
	uint8_t sample_eid = 10;
	const uint8_t eid_pool_size = 10;
	uint8_t expected_instance_id = 0x01;
	mctp_ctrl_cmd_allocate_eids_op operation = allocate_eids;
	uint8_t rq_d_inst = expected_instance_id | MCTP_CTRL_HDR_FLAG_REQUEST;
	struct mctp_ctrl_cmd_allocate_eids *cmd_allocate_eid = NULL;

	ret = mctp_encode_ctrl_cmd_allocate_eids(cmd_allocate_eid, rq_d_inst,
						 operation, eid_pool_size,
						 sample_eid);
	assert(ret == false);
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
	struct mctp_ctrl_cmd_get_networkid_req cmd_network_id;
	struct mctp_ctrl_msg_hdr hdr;
	cmd_network_id.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	cmd_network_id.ctrl_msg_hdr.rq_dgram_inst = 10;
	cmd_network_id.ctrl_msg_hdr.command_code = 20;

	assert(mctp_decode_ctrl_cmd_network_id_req(&cmd_network_id, &hdr));
	assert(cmd_network_id.ctrl_msg_hdr.ic_msg_type == hdr.ic_msg_type);
	assert(cmd_network_id.ctrl_msg_hdr.rq_dgram_inst == hdr.rq_dgram_inst);
	assert(cmd_network_id.ctrl_msg_hdr.command_code == hdr.command_code);
}

static void test_decode_ctrl_cmd_network_id_resp(void)
{
	int ret = 0;
	struct mctp_ctrl_cmd_network_id_resp cmd_network_id_resp;
	struct mctp_ctrl_msg_hdr hdr;
	struct mctp mctp;

	mctp.network_id.canonical.data1 = 10;
	cmd_network_id_resp.completion_code = MCTP_CTRL_CC_SUCCESS;
	cmd_network_id_resp.ctrl_msg_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	cmd_network_id_resp.ctrl_msg_hdr.rq_dgram_inst = 10;
	cmd_network_id_resp.ctrl_msg_hdr.command_code = 20;

	uint8_t completion_code;
	ret = mctp_decode_ctrl_cmd_network_id_resp(
		&cmd_network_id_resp, &hdr, &completion_code, &mctp.network_id);
	assert(!ret);
	assert(completion_code == cmd_network_id_resp.completion_code);
	assert(mctp.network_id.canonical.data1 ==
	       cmd_network_id_resp.network_id.canonical.data1);
	assert(cmd_network_id_resp.ctrl_msg_hdr.ic_msg_type == hdr.ic_msg_type);
	assert(cmd_network_id_resp.ctrl_msg_hdr.rq_dgram_inst ==
	       hdr.rq_dgram_inst);
	assert(cmd_network_id_resp.ctrl_msg_hdr.command_code ==
	       hdr.command_code);
}

int main(int argc, char *argv[])
{
	test_get_eid_encode();
	test_encode_ctrl_cmd_req_update_routing_info();
	test_encode_ctrl_cmd_rsp_get_routing_table();
	test_encode_ctrl_cmd_query_hop();
	test_allocate_eid_pool_encode();
	test_encode_ctrl_cmd_get_networkid_req();
	test_decode_ctrl_cmd_network_id_req();
	test_decode_ctrl_cmd_network_id_resp();
	/*Negative test cases */
	test_negative_encode_ctrl_cmd_query_hop();
	test_negation_allocate_eid_pool_encode();
	test_negation_encode_ctrl_cmd_get_networkid_req();
	return EXIT_SUCCESS;
}
