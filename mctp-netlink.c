/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mctp-netlink.h"
#include <string.h>
#include "libmctp.h"
#include "libmctp-log.h"
#include <err.h>
#include <errno.h>
#include <sys/param.h>
#include <ctype.h>
#include "ctrld/mctp-ctrl-log.h"

struct g_interface_data local_interface;
struct g_hw_info endpoint_hwinfo;
struct mctp_rtalter_msg {
	struct nlmsghdr nh;
	struct rtmsg rtmsg;
	uint8_t rta_buff[RTA_SPACE(sizeof(mctp_eid_t)) + // eid
			 RTA_SPACE(sizeof(int)) +	 // ifindex
			 100 // space for MTU, nexthop etc
	];
};

struct mctp_fq_addr {
	unsigned int net;
	mctp_eid_t eid;
};

typedef int (*decode_fn_t)(void *msg, size_t len, uint8_t id_exist);

int do_link_set(int ifindex, bool have_updown, bool up,
		       uint32_t mtu, bool have_net, uint32_t net);
void *mctp_get_rtnlmsg_attr(int rta_type, struct rtattr *rta, size_t len,
			    size_t *ret_len);
void mctp_hexdump(const void *b, int len, const char *indent);
int decode_rtnlmsgs(struct nlmsghdr *msg, size_t len,
		      int want_type, decode_fn_t decode_fn, uint8_t id_exist);

int update_interface_info(const char *ifname, const uint8_t *phy_addr,
			  const uint8_t phy_addlen, const uint8_t ifeid, uint32_t net, uint16_t mtu)
{
	if (!ifname || !phy_addr) {
		MCTP_ERR("%s invalid arg: failed to update interface data\n",
			 __func__);
		return -1;
	}
	memset(endpoint_hwinfo.phy_addr, 0x0, MAX_ADDR_LEN);
	memcpy(endpoint_hwinfo.phy_addr, phy_addr, phy_addlen);
	endpoint_hwinfo.phy_addlen = phy_addlen;
	memset(local_interface.ifname, '\0', MAX_INTERFACE_LEN);
	strncpy(local_interface.ifname, ifname, MAX_INTERFACE_LEN - 1);
	local_interface.ifeid = ifeid;
	local_interface.net = net;
	local_interface.mtu = mtu;
	return 0;
}

int mctp_nl_socket_init()
{
#if 0
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ifmsg;
		struct rtattr rta;
		uint8_t data[4];
	} msg = { 0 };
#endif
	mctp_eid_t eid = local_interface.ifeid;
	//struct sockaddr_nl nl_addr = { 0 };
	uint32_t ifindex = 0;
	int rc = 0;

	ifindex = if_nametoindex(local_interface.ifname);
	if (ifindex <= 0) {
		MCTP_ERR("%s Invalid interface index %d\n", __func__, ifindex);
		return -1;
	}
#if 0
	msg.nh.nlmsg_type = RTM_NEWADDR;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg.ifmsg.ifa_index = ifindex;
	msg.ifmsg.ifa_family = AF_MCTP;

	msg.rta.rta_type = IFA_LOCAL;
	msg.rta.rta_len = RTA_LENGTH(sizeof(eid));
	memcpy(msg.data, &eid, sizeof(eid));

	msg.nh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(msg.ifmsg)) +
				       RTA_SPACE(sizeof(eid)));
	//nl_addr.nl_family = AF_NETLINK;
	//nl_addr.nl_pid = 0;
#endif

	if (!local_interface.nl_sd) {
		/* Setup AF_NETLINK socket*/
		int nl_sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		int opt = 1;
		if (nl_sd < 0) {
			MCTP_ERR("open AF_NETLINK socket failed\n");
			rc = -1;
			goto out;
		}

		if ((rc = setsockopt(nl_sd, SOL_NETLINK, NETLINK_GET_STRICT_CHK,
				     &opt, sizeof(opt))) < 0) {
			MCTP_ERR(
				"AF_NETLINK socket[%d] setsockopt failed rc[%d] %s\n",
				nl_sd, rc, strerror(errno));
			close(nl_sd);
			goto out;
		}

		opt = 1;
		if ((rc = setsockopt(nl_sd, SOL_NETLINK, NETLINK_EXT_ACK, &opt,
				     sizeof(opt))) < 0) {
			MCTP_ERR(
				"AF_NETLINK socket[%d] setsockopt failed rc[%d] %s\n",
				nl_sd, rc, strerror(errno));
			close(nl_sd);
			goto out;
		}

		local_interface.nl_sd = nl_sd;
	}
	mctp_nl_add_addr(eid);
	do_link_set(ifindex, true, true, local_interface.mtu, false, local_interface.net);
	mctp_nl_get_link(0);
	
#if 0	
	/* Reason for false positive - Checked the length for Out-of-bounds write */
	/* coverity[overrun-buffer-arg : FALSE] */		
	if (eid > 0 && (rc = sendto(local_interface.nl_sd, (void *)&msg.nh,
			 msg.nh.nlmsg_len, 0, (struct sockaddr *)&nl_addr,
			 sizeof(nl_addr))) < 0) {
		MCTP_ERR(
			"%s failed to setup local EID %d for interface %s rc [%d] %s\n",
			__func__, eid, local_interface.ifname, rc,
			strerror(errno));
		goto out;
	}
#endif		
	return 0;
out:
	if (local_interface.nl_sd != 0) {
		close(local_interface.nl_sd);
		local_interface.nl_sd = 0;
	}
	return rc;
}


struct mctp_neighalter_msg {
	struct nlmsghdr nh;
	struct ndmsg ndmsg;
	uint8_t rta_buff[RTA_SPACE(1) + RTA_SPACE(MAX_ADDR_LEN)];
};

/* Returns the space used */
size_t mctp_put_rtnlmsg_attr(struct rtattr **prta, size_t *rta_len,
			     unsigned short type, const void *value,
			     size_t val_len)
{
	struct rtattr *rta = *prta;
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(val_len);
	memcpy(RTA_DATA(rta), value, val_len);
	*prta = RTA_NEXT(*prta, *rta_len);
	return RTA_SPACE(val_len);
}


static void dump_nlmsg_hdr(struct nlmsghdr *hdr, const char *indent)
{
	printf("%slen:   %d\n", indent, hdr->nlmsg_len);
	printf("%stype:  %d\n", indent, hdr->nlmsg_type);
	printf("%sflags: %d\n", indent, hdr->nlmsg_flags);
	printf("%sseq:   %d\n", indent, hdr->nlmsg_seq);
	printf("%spid:   %d\n", indent, hdr->nlmsg_pid);
}

void mctp_display_nlmsg_error(struct nlmsgerr *errmsg,
			      size_t errlen)
{
	size_t rta_len, errstrlen;
	struct rtattr *rta;
	char *errstr;

	if (errlen < sizeof(*errmsg)) {
		printf("short error message (%zu bytes)\n", errlen);
		return;
	}
	// skip the whole errmsg->msg and following payload
	rta = (void *)errmsg + offsetof(struct nlmsgerr, msg) +
	      errmsg->msg.nlmsg_len;
	rta_len = (void *)errmsg + errlen - (void *)rta;

	if (!(errmsg->error == -EEXIST))
		printf("Error from kernel: %s (%d)\n", strerror(-errmsg->error),
		       errmsg->error);
	errstr = mctp_get_rtnlmsg_attr(NLMSGERR_ATTR_MSG, rta, rta_len,
				       &errstrlen);
	if (errstr) {
		errstrlen = strnlen(errstr, errstrlen);
		printf("  %*s\n", (int)errstrlen, errstr);
	}
}

void mctp_dump_nlmsg_error(struct nlmsgerr *errmsg,
			   size_t errlen)
{
	printf("error:\n");
	mctp_display_nlmsg_error( errmsg, errlen);
	printf("  error packet dump:\n");
	mctp_hexdump(errmsg, errlen, "    ");
	printf("  error in reply to message:\n");
	dump_nlmsg_hdr(&errmsg->msg, "    ");
}

/* Receive and handle a NLMSG_ERROR and return the error code */
static int handle_nlmsg_ack()
{
	char resp[4096];
	struct nlmsghdr *msg;
	int rc;
	size_t len;

	rc = recvfrom(local_interface.nl_sd, resp, sizeof(resp), 0, NULL, NULL);
	if (rc < 0)
		return rc;
	len = rc;
	msg = (void *)resp;

	rc = 0;
	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if (msg->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *errmsg = NLMSG_DATA(msg);
			size_t errlen = NLMSG_PAYLOAD(msg, 0);
			(void)errlen;
			if (errmsg->error) {
				//mctp_dump_nlmsg_error(errmsg,
				//				errlen);
				rc = errmsg->error;
				mctp_display_nlmsg_error( errmsg, errlen);
				MCTP_CTRL_INFO("handle_nlmsg_ack %d \n", errmsg->error);
			}
		} else {
			MCTP_CTRL_INFO("Received unexpected message type %d instead of status",
			      msg->nlmsg_type);							  
			//mctp_hexdump(msg, msg->nlmsg_len, "    ");
		}
	}
	return rc;
}

/*
 * Note that only rtnl_doit_func() handlers like RTM_NEWADDR
 * will automatically return a response to NLM_F_ACK, other requests
 * shouldn't have it set.
 */
int mctp_nl_send(struct nlmsghdr *msg)
{
	struct sockaddr_nl addr;
	int rc;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	rc = sendto(local_interface.nl_sd, msg, msg->nlmsg_len, 0,
				(struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0)
		return rc;

	if (rc != (int)msg->nlmsg_len)
		MCTP_CTRL_INFO("sendto: short send (%d, expected %d)", rc,
		      msg->nlmsg_len);

	if (msg->nlmsg_flags & NLM_F_ACK) {
		return handle_nlmsg_ack();
	}
	return 0;
}

static int fill_neighalter_args(struct mctp_neighalter_msg *msg,
				struct rtattr **prta, size_t *prta_len,
				mctp_eid_t eid)
{
	struct rtattr *rta;
	int ifindex;
	size_t rta_len;

	ifindex = if_nametoindex(local_interface.ifname);
	if (!ifindex) {
		MCTP_CTRL_INFO("invalid device %s", local_interface.ifname);
		return -1;
	}

	memset(msg, 0x0, sizeof(*msg));
	msg->nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg->ndmsg.ndm_ifindex = ifindex;
	msg->ndmsg.ndm_family = AF_MCTP;

	msg->nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg->ndmsg));
	rta_len = sizeof(msg->rta_buff);
	rta = (void *)msg->rta_buff;

	msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, NDA_DST,
						   &eid, sizeof(eid));
	if (endpoint_hwinfo.phy_addlen) 
		msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, NDA_LLADDR,
						  endpoint_hwinfo.phy_addr, endpoint_hwinfo.phy_addlen);
	if (prta)
		*prta = rta;
	if (prta_len)
		*prta_len = rta_len;
	return 0;
}

int mctp_nl_add_neigh(mctp_eid_t eid)
{
	struct mctp_neighalter_msg msg;
	struct rtattr *rta;
	int rc;
	size_t rta_len;

	rc = fill_neighalter_args(&msg, &rta, &rta_len, eid);
	if (rc) {
		return -1;
	}

	msg.nh.nlmsg_type = RTM_NEWNEIGH;

	return mctp_nl_send(&msg.nh);
}

int mctp_nl_del_neigh(mctp_eid_t eid)
{
	struct mctp_neighalter_msg msg;
	int rc;

	memset(&endpoint_hwinfo, 0, sizeof(struct g_hw_info));
	rc = fill_neighalter_args(&msg, NULL, NULL, eid);
	if (rc) {
		return -1;
	}

	msg.nh.nlmsg_type = RTM_DELNEIGH;
	return mctp_nl_send(&msg.nh);
}

static int fill_rtalter_args(struct mctp_rtalter_msg *msg,
			     struct rtattr **prta, size_t *prta_len,
			     mctp_eid_t eid, unsigned int extent, int ifindex,
			     const struct mctp_fq_addr *gw)
{
	struct rtattr *rta;
	size_t rta_len;

	if (!ifindex && (!gw || !gw->eid)) {
		MCTP_CTRL_INFO("invalid route output: no device or gateway");
		return -1;
	}

	if (extent > 0xff || (unsigned int)eid + extent > 0xfe) {
		MCTP_CTRL_INFO("invalid route extent %d %d", eid, extent);
		return -1;
	}

	memset(msg, 0x0, sizeof(*msg));
	msg->nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	msg->rtmsg.rtm_family = AF_MCTP;
	msg->rtmsg.rtm_type = RTN_UNICAST;
	msg->rtmsg.rtm_dst_len = extent;
	msg->rtmsg.rtm_type = RTN_UNICAST;

	msg->nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg->rtmsg));
	rta_len = sizeof(msg->rta_buff);
	rta = (void *)msg->rta_buff;

	msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(&rta, &rta_len, RTA_DST,
						   &eid, sizeof(eid));
	if (ifindex) {
		msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(
			&rta, &rta_len, RTA_OIF, &ifindex, sizeof(ifindex));
	} else if (gw) {
		msg->nh.nlmsg_len += mctp_put_rtnlmsg_attr(
			&rta, &rta_len, RTA_GATEWAY, gw, sizeof(*gw));
	} else
		return -1;

	if (prta)
		*prta = rta;
	if (prta_len)
		*prta_len = rta_len;

	return 0;
}

int mctp_nl_add_route(uint8_t eid)
{
	struct mctp_rtalter_msg msg;
	struct rtattr *rta;
	size_t rta_len;
	int rc;

	uint32_t ifindex = if_nametoindex(local_interface.ifname);

	rc = fill_rtalter_args(&msg, &rta, &rta_len, eid, 0, ifindex, NULL);
	if (rc) {
		return -1;
	}
	msg.nh.nlmsg_type = RTM_NEWROUTE;

	uint32_t mtu = local_interface.mtu;

	if (mtu != 0) {
		/* Nested
        RTA_METRICS
            RTAX_MTU
        */
		struct rtattr *rta1;
		size_t rta_len1, space1;
		uint8_t buff1[100];

		rta1 = (void *)buff1;
		rta_len1 = sizeof(buff1);
		space1 = 0;
		space1 += mctp_put_rtnlmsg_attr(&rta1, &rta_len1, RTAX_MTU,
						&mtu, sizeof(mtu));
		// TODO add metric
		msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(
			&rta, &rta_len, RTA_METRICS | NLA_F_NESTED, buff1,
			space1);
	}

	return mctp_nl_send(&msg.nh);
}

int mctp_nl_del_route(uint8_t eid)
{
	struct mctp_rtalter_msg msg;
	int rc;
	uint32_t ifindex = 0;
	
	ifindex = if_nametoindex(local_interface.ifname);
	if (ifindex <= 0) {
		MCTP_ERR("%s Invalid interface index %d\n", __func__, ifindex);
		return -1;
	}

	rc = fill_rtalter_args(&msg, NULL, NULL, eid, 0, ifindex, NULL);
	if (rc) {
		return rc;
	}
	msg.nh.nlmsg_type = RTM_DELROUTE;

	return mctp_nl_send(&msg.nh);
}

int mctp_update_endpoint_hwinfo(const void *phy_addr, size_t phy_addlen)
{
	if (phy_addlen == 2) {
		endpoint_hwinfo.phy_addr[0] = ((uint8_t*)phy_addr)[1];
		endpoint_hwinfo.phy_addr[1] = ((uint8_t*)phy_addr)[0];
	} else 
	memcpy(endpoint_hwinfo.phy_addr, phy_addr, phy_addlen);
	endpoint_hwinfo.phy_addlen = phy_addlen;
	return 0;
}

/* Common parts of RTM_NEWADDR and RTM_DELADDR */
struct mctp_addralter_msg {
	struct nlmsghdr nh;
	struct ifaddrmsg ifmsg;
	struct rtattr rta;
	uint8_t data[4];
};

static int fill_addralter_args(struct mctp_addralter_msg *msg,
			       struct rtattr **prta, size_t *prta_len,
			       mctp_eid_t eid, int ifindex)
{
	memset(msg, 0x0, sizeof(*msg));

	msg->nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	msg->ifmsg.ifa_index = ifindex;
	msg->ifmsg.ifa_family = AF_MCTP;

	msg->rta.rta_type = IFA_LOCAL;
	msg->rta.rta_len = RTA_LENGTH(sizeof(eid));
	memcpy(RTA_DATA(&msg->rta), &eid, sizeof(eid));

	msg->nh.nlmsg_len =
		NLMSG_LENGTH(sizeof(msg->ifmsg)) + RTA_SPACE(sizeof(eid));

	if (prta)
		*prta = &msg->rta;
	if (prta_len)
		*prta_len = msg->rta.rta_len;

	return 0;
}

static int mctp_nl_addr(mctp_eid_t eid, int rtm_command)
{
	struct mctp_addralter_msg msg;
	int rc;
	uint32_t ifindex = 0;

	ifindex = if_nametoindex(local_interface.ifname);
	if (ifindex <= 0) {
		MCTP_ERR("%s Invalid interface index %d\n", __func__, ifindex);
		return -1;
	}
	rc = fill_addralter_args(&msg, NULL, NULL, eid, ifindex);
	if (rc)
		return -1;

	msg.nh.nlmsg_type = rtm_command;

	return mctp_nl_send(&msg.nh);
}

int mctp_nl_add_addr(mctp_eid_t eid)
{
	return mctp_nl_addr(eid, RTM_NEWADDR);
}

int mctp_nl_del_addr(mctp_eid_t eid)
{
	return mctp_nl_addr(eid, RTM_DELADDR);
}

/* Pointer returned on match, optionally returns ret_len */
void *mctp_get_rtnlmsg_attr(int rta_type, struct rtattr *rta, size_t len,
			    size_t *ret_len)
{
	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type == rta_type) {
			if (ret_len) {
				*ret_len = RTA_PAYLOAD(rta);
			}
			return RTA_DATA(rta);
		}
	}
	if (ret_len) {
		*ret_len = 0;
	}
	return NULL;
}

bool mctp_get_rtnlmsg_attr_u32(int rta_type, struct rtattr *rta, size_t len,
			       uint32_t *ret_value)
{
	size_t plen;
	uint32_t *p = mctp_get_rtnlmsg_attr(rta_type, rta, len, &plen);
	if (p) {
		if (plen == sizeof(*ret_value)) {
			*ret_value = *p;
			return true;
		} else {
			MCTP_CTRL_INFO("Unexpected attribute length %zu for type %d",
			      plen, rta_type);
		}
	}
	return false;
}

bool mctp_get_rtnlmsg_attr_u8(int rta_type, struct rtattr *rta, size_t len,
			      uint8_t *ret_value)
{
	size_t plen;
	uint8_t *p = mctp_get_rtnlmsg_attr(rta_type, rta, len, &plen);
	if (p) {
		if (plen == sizeof(*ret_value)) {
			*ret_value = *p;
			return true;
		} else {
			MCTP_CTRL_INFO("Unexpected attribute length %zu for type %d",
			      plen, rta_type);
		}
	}
	return false;
}

bool mctp_get_rtnlmsg_fq_addr(int rta_type, struct rtattr *rta, size_t len,
			      struct mctp_fq_addr *addr)
{
	size_t plen;
	uint8_t *p = mctp_get_rtnlmsg_attr(rta_type, rta, len, &plen);
	if (p) {
		if (plen == sizeof(*addr)) {
			memcpy(addr, p, plen);
			return true;
		} else {
			MCTP_CTRL_INFO("Unexpected attribute length %zu for mctp_fq_addr",
			      plen);
		}
	}
	return false;
}

/* Returns if the last message is NLMSG_DONE, or isn't multipart */
static bool nlmsgs_are_done(struct nlmsghdr *msg, size_t len)
{
	bool done = false;
	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if (done)
			MCTP_CTRL_INFO("received message after NLMSG_DONE");
		done = (msg->nlmsg_type == NLMSG_DONE) ||
		       !(msg->nlmsg_flags & NLM_F_MULTI);
	}
	return done;
}

/* respp is optional for returned buffer, length is set in resp+lenp */
int mctp_nl_recv_all(int sd, struct nlmsghdr **respp,
		     size_t *resp_lenp)
{
	uint8_t *respbuf = NULL;
	struct nlmsghdr *resp = NULL;
	struct sockaddr_nl addr;
	socklen_t addrlen;
	size_t newlen, readlen, pos;
	bool done;
	int rc;

	if (respp) {
		*respp = NULL;
		*resp_lenp = 0;
	}

	pos = 0;
	done = false;

	// read all the responses into a single buffer
	while (!done) {
		rc = recvfrom(sd, NULL, 0, MSG_PEEK | MSG_TRUNC,
					  NULL, 0);
		if (rc < 0) {
			MCTP_CTRL_INFO("recvfrom(MSG_PEEK)");
			rc = -errno;
			goto out;
		}

		if (rc == 0) {
			if (pos == 0) {
				MCTP_CTRL_INFO("No response to message");
				return -1;
			} else {
				// No more datagrams
				break;
			}
		}

		readlen = rc;
		newlen = pos + readlen;
		respbuf = (uint8_t*)realloc(respbuf, newlen);
		if (!respbuf) {
			MCTP_CTRL_INFO("allocation of %zu failed", newlen);
			rc = -ENOMEM;
			goto out;
		}
		resp = (struct nlmsghdr *)respbuf + pos;

		addrlen = sizeof(addr);
		rc = recvfrom(sd, resp, readlen, MSG_TRUNC,
					  (struct sockaddr *)&addr, &addrlen);
		if (rc < 0) {
			MCTP_CTRL_INFO("recvfrom(MSG_PEEK)");
			rc = -errno;
			goto out;
		}

		if ((size_t)rc > readlen)
			MCTP_CTRL_INFO("recvfrom: extra message data? (got %d, exp %zd)",
			      rc, readlen);

		if (addrlen != sizeof(addr)) {
			warn("recvfrom: weird addrlen? (%d, expecting %zd)",
			     addrlen, sizeof(addr));
		}

		done = nlmsgs_are_done(resp, rc);
		pos = MIN(newlen, pos + rc);
	}

	rc = 0;
out:
	if (rc == 0 && respp) {
		*respp = (struct nlmsghdr *)respbuf;
		*resp_lenp = pos;
	} else {
		free(respbuf);
	}

	return rc;
}

/* respp is optional for returned buffer, length is set in resp+lenp */
int mctp_nl_query(struct nlmsghdr *msg, struct nlmsghdr **respp,
		  size_t *resp_lenp)
{
	int rc;

	if (respp) {
		*respp = NULL;
		*resp_lenp = 0;
	}

	rc = mctp_nl_send(msg);
	if (rc)
		return rc;

	return mctp_nl_recv_all(local_interface.nl_sd, respp, resp_lenp);
}

void print_hex_addr(const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (i > 0) {
			putchar(':');
		}
		MCTP_CTRL_INFO("%02x", data[i]);
	}
	MCTP_CTRL_INFO("\n");
}

void mctp_hexdump(const void *b, int len, const char *indent)
{
	const char *buf = b;
	const int row_len = 16;
	int i, j;

	for (i = 0; i < len; i += row_len) {
		char hbuf[row_len * strlen("00 ") + 1];
		char cbuf[row_len + strlen("|") + 1];

		for (j = 0; (j < row_len) && ((i + j) < len); j++) {
			unsigned char c = buf[i + j];

			sprintf(hbuf + j * 3, "%02x ", c);

			if (!isprint(c))
				c = '.';

			sprintf(cbuf + j, "%c", c);
		}

		strcat(cbuf, "|");

		MCTP_CTRL_INFO("%s%08x  %*s |%s\n", indent, i,
		       (int)(0 - sizeof(hbuf) + 1), hbuf, cbuf);
	}
}

static int decode_neighbour(void *p, size_t len, uint8_t id_exist)
{
	struct ndmsg *msg = p;
	size_t rta_len;
	struct rtattr *rta;
	uint8_t eid;
	uint8_t *lladdr;
	size_t lladdr_len;

	if (len < sizeof(*msg)) {
		MCTP_CTRL_INFO("not enough data for a ndmsg\n");
		return -1;
	}
	rta = (void *)(msg + 1);
	rta_len = len - sizeof(*msg);

	eid = 0;
	mctp_get_rtnlmsg_attr_u8(NDA_DST, rta, rta_len, &eid);
	lladdr = mctp_get_rtnlmsg_attr(NDA_LLADDR, rta, rta_len, &lladdr_len);

	if (lladdr && lladdr_len == 2)
		MCTP_CTRL_INFO("eid %d lladdr 0x%x:0x%x \n", eid, lladdr[0], lladdr[1]);
	else {
		MCTP_CTRL_INFO("eid %d lladdr ", eid);
		print_hex_addr(lladdr, lladdr_len);
	}

	if (eid == id_exist)
		return 1;
			return 0;
}

static int decode_route(void *p, size_t len, uint8_t id_exist)
{
	struct rtattr *rta, *rd_nest;
	size_t rta_len, attr_len;
	struct mctp_fq_addr gw;
	uint32_t ifindex, mtu;
	struct rtmsg *msg = p;
	bool has_gw, has_if;
	uint8_t dst;

	if (len < sizeof(*msg)) {
		MCTP_CTRL_INFO("not enough data for a rtmsg\n");
			return -1;
	}
	rta = (void *)(msg + 1);
	rta_len = len - sizeof(*msg);

	dst = 0;
	ifindex = 0;
	mtu = 0;
	mctp_get_rtnlmsg_attr_u8(RTA_DST, rta, rta_len, &dst);
	rd_nest = mctp_get_rtnlmsg_attr(RTA_METRICS, rta, rta_len, &attr_len);
	if (rd_nest) {
		mctp_get_rtnlmsg_attr_u32(RTAX_MTU, rd_nest, attr_len, &mtu);
	}
	has_if = mctp_get_rtnlmsg_attr_u32(RTA_OIF, rta, rta_len, &ifindex);
	has_gw = mctp_get_rtnlmsg_fq_addr(RTA_GATEWAY, rta, rta_len, &gw);

	if (has_gw) {
		MCTP_CTRL_INFO("eid min %d max %d net %d gw %d mtu %d\n", dst,
		       dst + msg->rtm_dst_len, gw.net, gw.eid, mtu);

	} else if (has_if) {
		MCTP_CTRL_INFO("eid min %d max %d ifindex %d mtu %d\n", dst,
		       dst + msg->rtm_dst_len, ifindex, mtu); 
	} else {
		MCTP_CTRL_INFO("eid min %d max %d <invalid dst!> mtu %d\n", dst,
		       dst + msg->rtm_dst_len, mtu);
	}
	if (id_exist == dst && ifindex == if_nametoindex(local_interface.ifname))
		return 1;
	return 0;
}

static int decode_ifinfo(void *p, size_t len, uint8_t id_exist)
{
	struct ifinfomsg *msg = p;
	size_t rta_len, nest_len, mctp_len;
	struct rtattr *rta, *rt_nest, *rt_mctp;
	char *name;
	const char *updown;
	uint8_t *addr;
	size_t name_len, addr_len;
	uint32_t mtu = 0;
	uint32_t net = 0;
	(void)id_exist;

	if (len < sizeof(*msg)) {
		MCTP_CTRL_INFO("not enough data for an ifinfomsg\n");
			return -1;
	}
	rta = (void *)(msg + 1);
	rta_len = len - sizeof(*msg);

	name = mctp_get_rtnlmsg_attr(IFLA_IFNAME, rta, rta_len, &name_len);
	if (!name) {
		MCTP_CTRL_INFO("Missing interface name");
		name = "???";
		name_len = strlen(name);
	}

	addr = mctp_get_rtnlmsg_attr(IFLA_ADDRESS, rta, rta_len, &addr_len);
	mctp_get_rtnlmsg_attr_u32(IFLA_MTU, rta, rta_len, &mtu);

	// Nested IFLA_MCTP_NET
	rt_mctp = NULL;
	rt_nest = mctp_get_rtnlmsg_attr(IFLA_AF_SPEC, rta, rta_len, &nest_len);
		if (rt_nest) {
		rt_mctp = mctp_get_rtnlmsg_attr(AF_MCTP, rt_nest, nest_len,
						&mctp_len);
		}
		if (!rt_mctp) {
		// Ignore other interfaces
		return 0;
		}
	if (!mctp_get_rtnlmsg_attr_u32(IFLA_MCTP_NET, rt_mctp, mctp_len,
				       &net)) {
		MCTP_CTRL_INFO("No network attribute from %*s", (int)name_len, name);
	}

	updown = msg->ifi_flags & IFF_UP ? "up" : "down";

	local_interface.up = msg->ifi_flags & IFF_UP;

	// not sure if will be NULL terminated, handle either
	name_len = strnlen(name, name_len);
	MCTP_CTRL_INFO("dev %*s index %d address ", (int)name_len, name,
	       msg->ifi_index);

	if (addr && addr_len)
		print_hex_addr(addr, addr_len);

	MCTP_CTRL_INFO(" net %d mtu %d %s\n", net, mtu, updown);
	return 0;
		}

int decode_addr(void *p, size_t len, uint8_t id_exist)
{
	struct ifaddrmsg *ifa = NULL;
	size_t rta_len, ifalen;
	struct rtattr *rta = NULL;
	mctp_eid_t eid = 0;
	(void)id_exist;

	ifa = p;
	ifalen = len;
	if (ifalen < sizeof(*ifa)) {
		MCTP_CTRL_INFO("kernel returned short ifaddrmsg");
		return -1;
	}

	if (ifa->ifa_family != AF_MCTP)
		return -1;

	rta = (void *)(ifa + 1);
	rta_len = ifalen - sizeof(*ifa);
	if (!mctp_get_rtnlmsg_attr_u8(IFA_LOCAL, rta, rta_len, &eid)) {
		MCTP_CTRL_INFO("not found IFA_LOCAL for decode_addr eid = %d", eid);
		return -1;
	}

	if (if_nametoindex(local_interface.ifname) == ifa->ifa_index) {
		local_interface.ifeid = eid;	
		MCTP_CTRL_INFO("decode_addr eid = %d", eid);
	}
	return 0;
		}

// Calls pretty printing decode_ function for wanted message type
int decode_rtnlmsgs(struct nlmsghdr *msg, size_t len,
		      int want_type, decode_fn_t decode_fn, uint8_t id_exist)
{
	/*
	if (ctx->verbose) {
		MCTP_CTRL_INFO("/---------- %zd bytes total from kernel\n", len);
		dump_rtnlmsgs(ctx, msg, len);
		MCTP_CTRL_INFO("\\----------------------------\n");
	}
	*/
	int rc = 0;
	for (; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if (msg->nlmsg_type == want_type) {
			rc = decode_fn(NLMSG_DATA(msg), NLMSG_PAYLOAD(msg, 0), id_exist);
			if (rc == 1) {
				MCTP_CTRL_INFO("decode_rtnlmsgs return %d exist", id_exist);
				return rc;
			}
		} else
			switch (msg->nlmsg_type) {
			case NLMSG_NOOP:
			case NLMSG_DONE:
				break;
			case NLMSG_ERROR:
				/*
				mctp_decode_nlmsg_error(ctx->nl,
							 NLMSG_DATA(msg),
							 NLMSG_PAYLOAD(msg, 0));
		*/
				break;
			default:
				//MCTP_CTRL_INFO("unknown nlmsg type\n");
				//mctp_hexdump(msg, sizeof(msg), "    ");
				break;
	}
	}
	return 0;
}

int mctp_nl_get_addr(uint8_t id_exist)
{
	int rc;
	struct nlmsghdr *resp = NULL;
	size_t len;
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ifmsg;
		struct rtattr rta;
		char ifname[16];
	} msg = { 0 };

	uint32_t ifindex = if_nametoindex(local_interface.ifname);
	if (ifindex <= 0) {
		MCTP_ERR("%s Invalid interface index %d\n", __func__, ifindex);
		return -1;
	}

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));

	msg.nh.nlmsg_type = RTM_GETADDR;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	msg.ifmsg.ifa_family = AF_MCTP;

	rc = mctp_nl_query(&msg.nh, &resp, &len);
	if (rc)
		return rc;

	rc = decode_rtnlmsgs(resp, len, RTM_NEWADDR, decode_addr, id_exist);
	free(resp);
	return rc;

}

int mctp_nl_get_route(uint8_t id_exist)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr nh;
		struct rtmsg rtmsg;
		// struct rtattr		rta;
	} msg = { 0 };
	size_t len;
	int rc;

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.rtmsg));

	msg.nh.nlmsg_type = RTM_GETROUTE;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

	msg.rtmsg.rtm_family = AF_MCTP;
	rc = mctp_nl_query(&msg.nh, &resp, &len);
	if (rc)
		return rc;

	rc = decode_rtnlmsgs(resp, len, RTM_NEWROUTE, decode_route, id_exist);
	free(resp);
	return rc;
}

int mctp_nl_get_neigh(uint8_t id_exist)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr nh;
		struct ndmsg ndmsg;
	} msg = { 0 };

	uint32_t ifindex = 0;
	size_t len;
	int rc;

	ifindex = if_nametoindex(local_interface.ifname);
	if (ifindex <= 0) {
		MCTP_ERR("%s Invalid interface index %d\n", __func__, ifindex);
		return -1;
	}
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ndmsg));
	msg.nh.nlmsg_type = RTM_GETNEIGH;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	msg.ndmsg.ndm_family = AF_MCTP;
	msg.ndmsg.ndm_ifindex = ifindex;

	rc = mctp_nl_query(&msg.nh, &resp, &len);
	if (rc)
		return rc;

	rc = decode_rtnlmsgs(resp, len, RTM_NEWNEIGH, decode_neighbour, id_exist);
	free(resp);
	return rc;
}

int mctp_nl_get_link(uint8_t id_exist)
{
	struct nlmsghdr *resp;
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifmsg;
	} msg = { 0 };
	int ifindex;
	size_t len;
	int rc;

	ifindex = if_nametoindex(local_interface.ifname);
	if (ifindex <= 0) {
		MCTP_ERR("%s Invalid interface index %d\n", __func__, ifindex);
		return -1;
	}

	local_interface.up = 0;
	
	msg.nh.nlmsg_type = RTM_GETLINK;
	msg.nh.nlmsg_flags = NLM_F_REQUEST;
	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));

	msg.ifmsg.ifi_index = ifindex;

	rc = mctp_nl_query(&msg.nh, &resp, &len);
	if (rc)
		return rc;

	rc = decode_rtnlmsgs(resp, len, RTM_NEWLINK, decode_ifinfo, id_exist);
	free(resp);
	return rc;
}

int do_link_set(int ifindex, bool have_updown, bool up,
		       uint32_t mtu, bool have_net, uint32_t net)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifmsg;
		/* Space for all attributes */
		uint8_t rta_buff[200];
	} msg = { 0 };
	struct rtattr *rta;
	size_t rta_len;

	msg.nh.nlmsg_type = RTM_NEWLINK;
	msg.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg.ifmsg.ifi_index = ifindex;

	msg.nh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifmsg));
	rta_len = sizeof(msg.rta_buff);
	rta = (void *)msg.rta_buff;

	if (have_updown) {
		msg.ifmsg.ifi_change |= IFF_UP;
		if (up)
			msg.ifmsg.ifi_flags |= IFF_UP;
	}

	if (mtu)
		msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(
			&rta, &rta_len, IFLA_MTU, &mtu, sizeof(mtu));

	if (have_net) {
		/* Nested
		IFLA_AF_SPEC
			AF_MCTP
				IFLA_MCTP_NET
				... future device properties
		*/
		struct rtattr *rta1, *rta2;
		size_t rta_len1, rta_len2, space1, space2;
		uint8_t buff1[100], buff2[100];

		rta2 = (void *)buff2;
		rta_len2 = sizeof(buff2);
		space2 = 0;
		if (net)
			space2 += mctp_put_rtnlmsg_attr(&rta2, &rta_len2,
							IFLA_MCTP_NET, &net,
							sizeof(net));
		rta1 = (void *)buff1;
		rta_len1 = sizeof(buff1);
		space1 = mctp_put_rtnlmsg_attr(&rta1, &rta_len1,
					       AF_MCTP | NLA_F_NESTED, buff2,
					       space2);
		msg.nh.nlmsg_len += mctp_put_rtnlmsg_attr(
			&rta, &rta_len, IFLA_AF_SPEC | NLA_F_NESTED, buff1,
			space1);
	}

	int rc = mctp_nl_send(&msg.nh);
	return rc;
}