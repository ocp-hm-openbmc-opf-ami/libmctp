
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

#include <stdlib.h>
#include <string.h>

#include "mctp-discovery-common.h"
#include "libmctp-cmds.h"
#include <systemd/sd-bus.h>
#include "ctrld/mctp-sdbus.h"
#include <dirent.h>
#include "mctp-utils.h"
#include <fcntl.h>
#include <sys/inotify.h>
#include <ctype.h>

extern mctp_msg_type_table_t *g_msg_type_entries;
extern mctp_routing_table_t *g_routing_table_entries;

#define MAX_EVENTS 1024
#define LEN_NAME 1024
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (MAX_EVENTS * (EVENT_SIZE + LEN_NAME))
#define MCTP_TRACE_FILE "mctp_trace_on"
#define MCTP_TRACE_DIRECTORY "/var/run"
#define MCTP_TRACE_FILE_PATH MCTP_TRACE_DIRECTORY"/"MCTP_TRACE_FILE

int wd, fd;

/* Global definitions */
uint8_t g_verbose_level = 0;

void mctp_set_sys_verbose_level(u_int8_t debug_devel) 
{
	g_verbose_level = debug_devel;
}

uint16_t mctp_ctrl_get_target_bdf(const mctp_cmdline_args_t *cmd)
{
	struct mctp_astpcie_pkt_private pvt_binding;

	// Get binding information
	if (cmd->binding_type == MCTP_BINDING_PCIE) {
		memcpy(&pvt_binding, &cmd->bind_info,
		       sizeof(struct mctp_astpcie_pkt_private));
	} else {
		MCTP_SYS_INFO("%s: Invalid binding type: %d\n", __func__,
			       cmd->binding_type);
		return 0;
	}

	/* Update the target EID */
	MCTP_SYS_INFO("%s: Target BDF: 0x%x\n", __func__,
		       pvt_binding.remote_id);
	return (pvt_binding.remote_id);
}

const char *phy_transport_binding_to_string(uint8_t id)
{
	if (id == 0x0) {
		/* It is defined unspecified in DSP0239 but we used for SPI type */
		return "SPI";
	} else if (id == 0x1) {
		/* MCTP over SMbus */
		return "SMBus";
	} else if (id == 0x2) {
		/*  MCTP over PCI */
		return "PCIe";
	} else if (id == 0x3) {
		/* MCTP over USB */
		return "USB";
	} else if (id == 0x04) {
		/* MCTP over KCS */
		return "KCS";
	} else if (id == 0x05) {
		/* MCTP over Serial*/
		return "Serial";
	} else if (id == 0x06) {
		/* MCTP over I3C*/
		return "I3C";
	} else if (id == 0xFF) {
		/* MCTP over VDM*/
		return "Vendor-Defined";
	}
	return "Unknown";
}

int64_t mctp_ext_millis()
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return ((int64_t)now.tv_sec) * 1000 + ((int64_t)now.tv_nsec) / 1000000;
}

int mctp_get_sys_verbose_level() {
    char buffer[2];

    int fd = open(MCTP_TRACE_FILE_PATH, O_RDONLY);
    if (fd < 0) {
        MCTP_SYS_ERR("mctp_get_sys_verbose_level open fail!\n");
        return 0;
    }

    ssize_t bytes_read;
	int level = 0;
    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
    }

	if (isdigit(buffer[0])) {
	    level = buffer[0] - '0';
	} else {
		level = buffer[0];
	}

	if (!(level > MCTP_SYS_LOG_NONE && level <= MCTP_SYS_LOG_TRACE))
	    level = 0;

    close(fd);
	return level;
}

int mctp_handle_sys_trace_event() 
{
    char buffer[BUF_LEN];
    int length, i = 0;
 
	length = read(fd, buffer, BUF_LEN);
	if (length < 0) {
		MCTP_SYS_ERR("mctp_handle_sys_trace_event read error\n");
		return -1;
	}

	char event_name[LEN_NAME];
	/* coverity[remediation : FALSE] */		
	while (i < length) {
		struct inotify_event *event = (struct inotify_event *) &buffer[i];
		memset(event_name, 0, sizeof(event_name));
		/* coverity[illegal_address : FALSE] */		
		/* coverity[string_null : FALSE] */		
		snprintf(event_name, sizeof(event_name) - 1, "%s", event->name);

		if (event->len) {
			if (event->mask & IN_CREATE) {
				if (event->mask & IN_ISDIR) {
					MCTP_SYS_DEBUG("The directory %s was created.\n", event_name);
				} else if(strstr(event_name, MCTP_TRACE_FILE)) {
					return mctp_get_sys_verbose_level();
				}
			}
			if (event->mask & IN_MODIFY) {
				if (event->mask & IN_ISDIR) {
					MCTP_SYS_DEBUG("The directory %s was modified.\n", event_name);
				} else if(strstr(event_name, MCTP_TRACE_FILE)) {
					return mctp_get_sys_verbose_level();
				}
			}
			if (event->mask & IN_DELETE) {
				if (event->mask & IN_ISDIR) {
					MCTP_SYS_DEBUG("The directory %s was deleted.\n", event_name);
				} else if(strstr(event_name, MCTP_TRACE_FILE)) {
					return 0;
				}
			}
			i += EVENT_SIZE + event->len;
		} else {
			break;
		}
	}
	return -1;
}

int mctp_sys_trace_init() 
{
    fd = inotify_init();
    if (fd < 0) {
         MCTP_SYS_ERR("Couldn't initialize inotify\n");
    }

    wd = inotify_add_watch(fd, MCTP_TRACE_DIRECTORY, IN_CREATE | IN_MODIFY | IN_DELETE);
    if (wd == -1) {
         MCTP_SYS_DEBUG("Couldn't add watch to %s\n", MCTP_TRACE_FILE);
    } else {
         MCTP_SYS_DEBUG("inotify watching: %s\n", MCTP_TRACE_FILE);
    }
	return fd;
}

int mctp_sys_trace_clean_up() 
{
    inotify_rm_watch(fd, wd);
    close(fd);

    return 0;
}
