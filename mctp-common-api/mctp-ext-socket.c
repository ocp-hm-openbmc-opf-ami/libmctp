#include <bits/time.h>
#define _GNU_SOURCE

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h>

#include "mctp-ctrl-cmdline.h"
#include "libmctp-astpcie.h"
#include "mctp-ctrl.h"
#include "libmctp-log.h"
#include "mctp-ext-socket.h"
#include "mctp-utils.h"

/* Set MCTP message Type */
const uint8_t MCTP_CTRL_MSG_TYPE = 0;
const uint8_t MCTP_MSG_TYPE_HDR = 0;

/* Global definitions */
uint8_t g_verbose_level = 1;

mctp_requester_rc_t mctp_msg_client_with_binding_send(
	mctp_eid_t dest_eid, int mctp_fd, const uint8_t *mctp_req_msg,
	size_t req_msg_len, const uint8_t *mctp_hdr_msg,
	const mctp_binding_ids_t *bind_id, void *mctp_binding_info,
	size_t mctp_binding_len)
{
	uint8_t hdr[2] = { dest_eid, MCTP_MSG_TYPE_HDR };
	struct iovec iov[5];

	MCTP_ASSERT_RET(mctp_req_msg[0] == MCTP_MSG_TYPE_HDR,
			MCTP_REQUESTER_SEND_FAIL, " unsupported Msg type: %d\n",
			mctp_req_msg[0]);

	/* Binding ID and information */
	iov[0].iov_base = (uint8_t *)bind_id;
	iov[0].iov_len = sizeof(uint8_t);
	iov[1].iov_base = (uint8_t *)mctp_binding_info;
	iov[1].iov_len = mctp_binding_len;

	/* MCTP header and payload */
	iov[2].iov_base = hdr;
	iov[2].iov_len = sizeof(hdr);
	iov[3].iov_base = (uint8_t *)(mctp_req_msg + 1);
	iov[3].iov_len = req_msg_len;
	iov[4].iov_base = (uint8_t *)mctp_hdr_msg;
	iov[4].iov_len = sizeof(struct mctp_hdr);

	struct msghdr msg = { 0 };
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

	mctp_trace_common("mctp_bind_id  >> ", (uint8_t *)bind_id,
			  sizeof(uint8_t));
	mctp_trace_common("mctp_pvt_data >> ", mctp_binding_info,
			  mctp_binding_len);
	mctp_trace_common("mctp_req_hdr  >> ", hdr, sizeof(hdr));
	mctp_trace_common("mctp_req_msg  >> ", mctp_req_msg, req_msg_len);

	ssize_t rc = sendmsg(mctp_fd, &msg, 0);
	MCTP_ASSERT_RET(rc >= 0, MCTP_REQUESTER_SEND_FAIL,
			"failed to sendmsg\n");

	return MCTP_REQUESTER_SUCCESS;
}

static mctp_requester_rc_t
mctp_msg_recv(mctp_eid_t eid, int mctp_fd, uint8_t **mctp_resp_msg,
	      size_t *resp_msg_len, uint8_t **mctp_hdr_msg, uint16_t *remote_id,
	      mctp_eid_t *resp_eid)
{
	uint8_t tag = 0;
	size_t mctp_prefix_len = sizeof(tag) + sizeof(eid);
	uint8_t mctp_prefix[mctp_prefix_len];
	struct iovec iov[3];
	size_t mctp_len;
	size_t min_len = sizeof(tag) + sizeof(eid) + sizeof(MCTP_MSG_TYPE_HDR) +
			 sizeof(struct mctp_hdr_ext_);
	ssize_t length;

	length = recv(mctp_fd, NULL, 0, MSG_PEEK | MSG_TRUNC);

	if (length < 0 && errno == EAGAIN) {
		mctp_prinfo("%s: Recv failed: due to timedout\n", __func__);
		return MCTP_REQUESTER_TIMEOUT;
	}

	if ((length <= 0) || (length > MCTP_MAX_MESSAGE_SIZE)) {
		mctp_prinfo(
			"%s: Recv failed: Invalid length: %zi or timedout\n",
			__func__, length);
		return MCTP_REQUESTER_RECV_FAIL;
	} else if (length < (ssize_t)min_len) {
		/* read and discard */
		uint8_t buf[length];

		length = recv(mctp_fd, buf, length, 0);
		mctp_trace_common("mctp_recv_msg_invalid_len", buf, length);
		return MCTP_REQUESTER_INVALID_RECV_LEN;
	} else {
		mctp_len =
			length - mctp_prefix_len - sizeof(struct mctp_hdr_ext_);

		iov[0].iov_len = mctp_prefix_len;
		iov[0].iov_base = mctp_prefix;

		*mctp_resp_msg = malloc(mctp_len);
		*mctp_hdr_msg = malloc(sizeof(struct mctp_hdr_ext_));

		MCTP_ASSERT_RET(*mctp_resp_msg != NULL,
				MCTP_REQUESTER_RECV_FAIL,
				"fail to allocate %zu bytes memory\n",
				mctp_len);

		iov[1].iov_len = mctp_len;
		iov[1].iov_base = *mctp_resp_msg;

		iov[2].iov_len = sizeof(struct mctp_hdr_ext_);
		iov[2].iov_base = *mctp_hdr_msg;

		struct msghdr msg = { 0 };
		msg.msg_iov = iov;
		msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
		int bytes = recvmsg(mctp_fd, &msg, 0);

		mctp_trace_common("mctp_prefix_msg", mctp_prefix,
				  mctp_prefix_len);
		mctp_trace_common("mctp_resp_msg", *mctp_resp_msg, mctp_len);

		if (length != bytes) {
			MCTP_SYS_ERR(
				"%s: free mctp_resp_msg MCTP_REQUESTER_INVALID_RECV_LEN\n",
				__func__);
			free(*mctp_resp_msg);
			return MCTP_REQUESTER_INVALID_RECV_LEN;
		}
		*resp_eid = mctp_prefix[1];
		*remote_id = (**mctp_hdr_msg << 8) | *(*mctp_hdr_msg + 1);

		/* Update the response length */
		*resp_msg_len = mctp_len;

		mctp_prdebug("%s: resp_msg_len: %zu, mctp_len: %zu\n", __func__,
			     *resp_msg_len, mctp_len);
		return MCTP_REQUESTER_SUCCESS;
	}

	return MCTP_REQUESTER_SUCCESS;
}

/* The function will check EID and ignore the incomming response and receive
 * the response again if EID mismatches.
 * */
mctp_requester_rc_t mctp_client_sync_recv(mctp_eid_t *eid, int mctp_fd,
					  uint8_t **mctp_resp_msg,
					  size_t *resp_msg_len,
					  uint8_t **mctp_hdr_msg,
					  uint16_t *remote_id)
{
	mctp_eid_t resp_eid;
	mctp_requester_rc_t rc;
	/*
    struct pollfd fds[1];
    fds[0].fd = mctp_fd;
    fds[0].events = POLLIN;
	int ret = poll(fds, 1, 1000); 
	if (ret == -1) {
		return MCTP_REQUESTER_RECV_FAIL;
	}
*/
	rc = mctp_msg_recv(*eid, mctp_fd, mctp_resp_msg, resp_msg_len,
			   mctp_hdr_msg, remote_id, &resp_eid);
	if (rc == MCTP_REQUESTER_SUCCESS) {
		mctp_prdebug("%s: I'm not the requester - %d, EID: %d\n",
			     __func__, *eid, resp_eid);
		*eid = resp_eid;
		return rc;
	}
	return MCTP_REQUESTER_TIMEOUT;
}
