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
#include "mctp-ctrl-log.h"

/* Set MCTP message Type */
const uint8_t MCTP_CTRL_MSG_TYPE = 0;
const uint8_t MCTP_MSG_TYPE_HDR = 0;

#ifdef MCTP_IN_KERNEL
/* MCTP Tx/Rx timeouts */
#define MCTP_CTRL_TXRX_TIMEOUT_MICRO_SECS 0

/* MCTP TX/RX retry threshold */
#define MCTP_CMD_THRESHOLD 2

#include "mctp-netlink.h"

extern struct g_interface_data local_interface;
extern struct g_hw_info endpoint_hwinfo;


mctp_requester_rc_t mctp_endpoint_socket_init(int *fd, const char *path,
					 uint8_t msgtype, time_t time_out)
{
	int rc = 0;
	/* Setup AF_MCTP socket*/
	struct timeval timeout = { 0 };
	struct sockaddr_mctp addr = { 0 };

	/* Set timeout as 5 seconds */
	timeout.tv_sec = time_out;
	timeout.tv_usec = MCTP_CTRL_TXRX_TIMEOUT_MICRO_SECS;
	(void)path;
	(void)msgtype;

	*fd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (*fd < 0) {
		MCTP_ERR("open AF_MCTP socket failed");
		goto out;
	}

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = MCTP_NET_ANY;
	addr.smctp_addr.s_addr = MCTP_ADDR_ANY;//local_interface.ifeid;
	addr.smctp_type = 0;
	addr.smctp_tag = MCTP_TAG_OWNER;

	if ((rc = bind(*fd, (struct sockaddr *)&addr, sizeof(addr))) < 0) {
		MCTP_ERR("AF_MCTP socket[%d] bind failed: rc [%d] %s\n", *fd,
			 rc, strerror(errno));
		goto out;
	}

	/* Register socket operations timeouts */
	if ((rc = setsockopt(*fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
			     sizeof(timeout))) < 0) {
		MCTP_ERR("AF_MCTP socket[%d] setsockopt failed: rc[%d] %s\n",
			 *fd, rc, strerror(errno));
		goto out;
	}

	int val = 1;
	if ((rc = setsockopt(*fd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &val,
			     sizeof(val)))) {
		MCTP_ERR("AF_MCTP socket[%d] setsockopt failed: rc[%d] %s\n",
			 *fd, rc, strerror(errno));
		goto out;
	}

	return MCTP_REQUESTER_SUCCESS;
out:
	if (*fd >= 0) {
		close(*fd);
		*fd = -1;
	}

	return MCTP_REQUESTER_OPEN_FAIL;
}

mctp_requester_rc_t mctp_client_sync_send(mctp_eid_t dest_eid, int mctp_fd,
				     uint8_t msgtype,
				     const uint8_t *mctp_req_msg,
				     size_t req_msg_len,
					 uint8_t msgtag)
{
	struct sockaddr_mctp addr = { 0 };
	int rc = 0;

	if (mctp_fd < 0) {
		mctp_prerr("%s: Failed to create socket for mctp_fd %d: %s",
			   __func__, mctp_fd, strerror(errno));
		return MCTP_REQUESTER_SEND_FAIL;
	}

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = MCTP_NET_ANY; /* any network */
	addr.smctp_addr.s_addr = dest_eid; /* remote eid */
	addr.smctp_tag = msgtag;//MCTP_TAG_OWNER; /* kernel will allocate an owned tag */
	addr.smctp_type = msgtype;

	rc = sendto(mctp_fd, mctp_req_msg, req_msg_len, 0,
		    (struct sockaddr *)&addr, sizeof(addr));
	if (rc != (int)req_msg_len) {
		mctp_prerr(
			"%s: Failed to send message on mctp_fd %d. Sent %d bytes, expected %d bytes: %s",
			__func__, mctp_fd, rc, (int)req_msg_len,
			strerror(errno));
		err(EXIT_FAILURE, "sendto(%zd) - rc: %d", req_msg_len, rc);
		return MCTP_REQUESTER_SEND_FAIL;
	}

	return MCTP_REQUESTER_SUCCESS;
}

mctp_requester_rc_t mctp_client_send_ext(mctp_eid_t dest_eid, int mctp_fd,
					 uint8_t msgtype,
					 const uint8_t *mctp_req_msg,
					 size_t req_msg_len)
{
	struct sockaddr_mctp_ext addr = { 0 };
	socklen_t addrlen;
	int rc = 0;
	int ifindex = 0;

	if (mctp_fd < 0) {
		mctp_prerr("%s: Invalid socket descriptor mctp_fd %d: %s",
			   __func__, mctp_fd, strerror(errno));
		return MCTP_REQUESTER_SEND_FAIL;
	}

	ifindex = if_nametoindex(local_interface.ifname);
	if (ifindex <= 0) {
		mctp_prerr("%s Invalid ifindex %d", __func__, ifindex);
		return MCTP_REQUESTER_SEND_FAIL;
	}

	addrlen = sizeof(struct sockaddr_mctp);
	addr.smctp_base.smctp_family = AF_MCTP;
	addr.smctp_base.smctp_network = 1;
	addr.smctp_base.smctp_addr.s_addr = dest_eid;
	addr.smctp_base.smctp_type = msgtype;
	addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;

	addrlen = sizeof(struct sockaddr_mctp_ext);
	memcpy(addr.smctp_haddr, endpoint_hwinfo.phy_addr,
	       endpoint_hwinfo.phy_addlen);
	addr.smctp_halen = endpoint_hwinfo.phy_addlen;
	addr.smctp_ifindex = ifindex;

	/* send data */
	rc = sendto(mctp_fd, mctp_req_msg, req_msg_len, 0,
		    (struct sockaddr *)&addr, addrlen);
	if (rc != (int)req_msg_len) {
		err(EXIT_FAILURE, "%s: sendto(%zd) - rc: %d Error %s", __func__,
		    req_msg_len, rc, strerror(errno));
		return MCTP_REQUESTER_SEND_FAIL;
	}

	return MCTP_REQUESTER_SUCCESS;
}

mctp_requester_rc_t
mctp_msg_client_with_binding_send(mctp_eid_t dest_eid, int mctp_fd,
			      const uint8_t *mctp_req_msg, size_t req_msg_len,
				  const uint8_t *mctp_hdr_msg,
			      const mctp_binding_ids_t *bind_id,
			      void *mctp_binding_info, size_t mctp_binding_len)
{
	(void)mctp_hdr_msg;
	(void)bind_id;
	(void)mctp_binding_info;
	(void)mctp_binding_len;

	if (dest_eid == MCTP_EID_BROADCAST || dest_eid == MCTP_EID_NULL) {
		return mctp_client_send_ext(dest_eid, mctp_fd, 0,
					    mctp_req_msg + 1, req_msg_len - 1);

	} else
		return mctp_client_sync_send(dest_eid, mctp_fd, 0, mctp_req_msg + 1,
					req_msg_len - 1, ((struct mctp_hdr_ext_*)mctp_hdr_msg)->flags_seq_tag);

}

static mctp_requester_rc_t mctp_endpoint_recv(mctp_eid_t eid, int mctp_fd,
				     uint8_t **mctp_resp_msg,
				     size_t *resp_msg_len, uint8_t **mctp_hdr_msg, mctp_eid_t *resp_eid)
{
	(void)eid;
	struct sockaddr_mctp addr = { 0 };
	socklen_t addrlen;
	ssize_t ret = 0;
	ssize_t bufLen = 0;
	addrlen = sizeof(addr);

	addr.smctp_family = AF_MCTP;
	addr.smctp_network = MCTP_NET_ANY; /* any network */
	addr.smctp_addr.s_addr = eid;	   /* remote eid */
	addr.smctp_tag = MCTP_TAG_OWNER; /* kernel will allocate an owned tag */
	addr.smctp_type = 0;

	bufLen = recv(mctp_fd, NULL, 0, MSG_PEEK | MSG_TRUNC);

	if (bufLen < 0) {
		mctp_prinfo("%s: Recv failed: due to timedout\n", __func__);
		return MCTP_REQUESTER_TIMEOUT;
	}

	if (bufLen >= (ssize_t)(SIZE_MAX >> 1)) {
		mctp_prerr("%s: Recv len is invalid\n", __func__);
		return MCTP_REQUESTER_INVALID_RECV_LEN;
	}

	*mctp_resp_msg = malloc(bufLen + 1);
	*mctp_hdr_msg = malloc(sizeof(struct mctp_hdr_ext_));

	MCTP_ASSERT_RET(*mctp_resp_msg != NULL, MCTP_REQUESTER_RECV_FAIL,
			"fail to allocate %zu bytes memory\n", bufLen);

	ret = recvfrom(mctp_fd, *mctp_resp_msg + 1, bufLen, MSG_TRUNC,
		       (struct sockaddr *)&addr, &addrlen);

	if (ret != bufLen) {
		err(EXIT_FAILURE, "Unexpected length of receive buffer");
		return MCTP_REQUESTER_RECV_FAIL;
	}
	
	*resp_msg_len = bufLen + 1;
	(*mctp_resp_msg)[0] = addr.smctp_type;
	*resp_eid = addr.smctp_addr.s_addr;
	((struct mctp_hdr_ext_*)*mctp_hdr_msg)->flags_seq_tag = addr.smctp_tag &~MCTP_TAG_OWNER;
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
	(void) remote_id;
	(void) mctp_hdr_msg;

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
	rc = mctp_endpoint_recv(*eid, mctp_fd, mctp_resp_msg, resp_msg_len, mctp_hdr_msg,
		 &resp_eid);
	if (rc == MCTP_REQUESTER_SUCCESS) {
		mctp_prdebug("%s: I'm not the requester - %d, EID: %d\n",
			     __func__, *eid, resp_eid);
		*eid = resp_eid;
		return rc;
	}
	return MCTP_REQUESTER_TIMEOUT;
}
#else 

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
			  sizeof(uint8_t), dest_eid);
	mctp_trace_common("mctp_pvt_data >> ", mctp_binding_info,
			  mctp_binding_len, dest_eid);
	mctp_trace_common("mctp_req_hdr  >> ", hdr, sizeof(hdr), dest_eid);
	mctp_trace_common("mctp_req_msg  >> ", mctp_req_msg, req_msg_len, dest_eid);

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
		mctp_trace_common("mctp_recv_msg_invalid_len", buf, length, eid);
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
				  mctp_prefix_len, eid);
		mctp_trace_common("mctp_resp_msg", *mctp_resp_msg, mctp_len, eid);

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

#endif