/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

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
	assert(mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, entries, 1,
							  &new_size));
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

	assert(!mctp_encode_ctrl_cmd_rsp_get_routing_table(NULL, entries, 1,
							   &new_size));
	assert(!mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, NULL, 1,
							   &new_size));
	assert(!mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, entries, 1,
							   NULL));
	assert(mctp_encode_ctrl_cmd_rsp_get_routing_table(&resp, entries, 0,
							  &new_size));
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

int main(int argc, char *argv[])
{
	test_get_eid_encode();
	test_encode_ctrl_cmd_req_update_routing_info();
	test_encode_ctrl_cmd_rsp_get_routing_table();
	test_encode_ctrl_cmd_query_hop();
	test_check_encode_cc_only_response();
	test_allocate_eid_pool_encode_req();
	test_allocate_eid_pool_encode_resp();
	test_allocate_eid_pool_decode_req();
	test_allocate_eid_pool_decode_resp();
	test_mctp_encode_ctrl_cmd_get_network_id_resp();
	test_encode_ctrl_cmd_get_networkid_req();
	/*Negative test cases */
	test_negation_allocate_eid_pool_encode_req();
	test_negation_allocate_eid_pool_encode_resp();
	test_negation_allocate_eid_pool_decode_req();
	test_negation_allocate_eid_pool_decode_resp();
	test_negative_encode_ctrl_cmd_query_hop();
	test_negation_encode_ctrl_cmd_get_networkid_req();
	test_negative_encode_cc_only_response();
	return EXIT_SUCCESS;
}
