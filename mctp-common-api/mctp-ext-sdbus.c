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
#include "mctp-ext-sdbus.h"
#include "mctp-utils.h"

extern mctp_msg_type_table_t *g_msg_type_entries;
extern mctp_routing_table_t *g_routing_table_entries;
extern int g_msg_type_table_len;
extern int g_routing_table_length;

bool check_endpoint_discovered(uint8_t eid)
{
	mctp_msg_type_table_t *entry = g_msg_type_entries;
	while (entry != NULL) {
		if (entry->eid == eid) {
			MCTP_SYS_ERR(
				"check_endpoint_discovered entry->eid %d eid %d\n",
				entry->eid, eid);
			return 1;
		}
		entry = entry->next;
	}
	return 0;
}

/** To remove single entry by UUID key */
int mctp_ctrl_sdbus_object_remove_invalid_eid(sd_bus *bus)
{
	if (g_routing_table_entries) {
		mctp_routing_table_t *entry = g_routing_table_entries;
		while (entry) {
			if (GET_ROUTING_ENTRY_TYPE(entry->routing_table.entry_type) == MCTP_ROUTING_ENTRY_ENDPOINT &&
				check_endpoint_discovered(entry->routing_table.starting_eid) && !entry->valid)
				mctp_ctrl_sdbus_object_remove_eid(bus, entry->routing_table.starting_eid);
			entry = entry->next;
		}
	}

	return 0;
}

int mctp_ctrl_sdbus_object_remove_all_signal(sd_bus *bus)
{
	char mctp_ctrl_objpath[MCTP_CTRL_SDBUS_OBJ_PATH_SIZE];
	mctp_msg_type_table_t *entry = g_msg_type_entries;

	while (entry != NULL) {
		/* Reset the message buffer */
		memset(mctp_ctrl_objpath, '\0', MCTP_CTRL_SDBUS_OBJ_PATH_SIZE);

		/* Frame the message */
		snprintf(mctp_ctrl_objpath, MCTP_CTRL_SDBUS_OBJ_PATH_SIZE,
			 "%s%d", MCTP_CTRL_NW_OBJ_PATH, entry->eid);

		sd_bus_emit_object_removed(bus, mctp_ctrl_objpath);
		entry = entry->next;
	}
	return 0;
}

int mctp_ctrl_sdbus_object_remove_eid(sd_bus *bus, mctp_eid_t eid)
{
	mctp_msg_type_table_t *prev = NULL, *curr = NULL;
	for (curr = g_msg_type_entries; curr; curr = curr->next) {
		if (curr->eid == eid) {
			char mctp_ctrl_objpath[MCTP_CTRL_SDBUS_OBJ_PATH_SIZE];
			/* Reset the message buffer */
			memset(mctp_ctrl_objpath, '\0',
			       MCTP_CTRL_SDBUS_OBJ_PATH_SIZE);

			/* Frame the message */
			snprintf(mctp_ctrl_objpath,
				 MCTP_CTRL_SDBUS_OBJ_PATH_SIZE, "%s%d",
				 MCTP_CTRL_NW_OBJ_PATH, curr->eid);

			sd_bus_emit_object_removed(bus, mctp_ctrl_objpath);
			for (int i = 0; i < MCTP_DBUS_SLOT_MAX_SIZE; i++) {
				if (curr->slot[i])
					sd_bus_slot_unref(curr->slot[i]);
			}
			mctp_uuid_entry_remove(eid);
			mctp_vdm_entry_remove(eid);

			if (prev)
				prev->next = curr->next;
			else
				g_msg_type_entries = curr->next;
			free(curr);
			--g_msg_type_table_len;
			return 0;
		}
		prev = curr;
	}
	return -1;
}
