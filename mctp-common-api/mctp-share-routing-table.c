#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "libmctp-log.h"
#include "libmctp.h"
#include "mctp-share-routing-table.h"
#include "mctp-utils.h"


#define MAX_ROUTING_TABLE_ENTRY 24

typedef struct mctp_routing_table_cache {
	int eid;
	uint8_t	media_type;
	uint8_t routing_table[sizeof(struct get_routing_table_entry) *MAX_ROUTING_TABLE_ENTRY];
	struct mctp_routing_table_cache *next;
	uint16_t offset;
} mctp_routing_table_cache_t;

mctp_routing_table_cache_t* g_mctp_routing_table_cache = NULL;

void mctp_get_routing_table_entry_remote_id(mctp_eid_t eid, uint16_t *remote_id,
					    uint8_t phys_transport_binding_id)
{
	mctp_routing_table_cache_t* mctp_routing_table_cache = g_mctp_routing_table_cache;
	
	while(mctp_routing_table_cache != NULL) {
		struct get_routing_table_entry *entry = (struct get_routing_table_entry *) mctp_routing_table_cache -> routing_table;
		int i = 0;
		while (entry != NULL && i++ < MAX_ROUTING_TABLE_ENTRY) {
			if (entry ->starting_eid == 0)
				break;
			if ((GET_ROUTING_ENTRY_TYPE(entry->entry_type) == MCTP_ROUTING_ENTRY_ENDPOINTS || 
					GET_ROUTING_ENTRY_TYPE(entry->entry_type) == MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS) &&
				eid >= entry->starting_eid &&
				eid < entry->starting_eid + entry->eid_range_size &&
				entry->phys_transport_binding_id ==
					phys_transport_binding_id) {
				*remote_id = entry->phys_address[0] << 8 |
						entry->phys_address[1];
				return;
			}
			entry = (struct get_routing_table_entry *) ((uint8_t*) entry + sizeof(struct get_routing_table_entry) - entry->phys_address_size % 2);
		}
		mctp_routing_table_cache = mctp_routing_table_cache->next;
	}

	mctp_routing_table_cache = g_mctp_routing_table_cache;
	while(mctp_routing_table_cache != NULL) {
		struct get_routing_table_entry *entry = (struct get_routing_table_entry *) mctp_routing_table_cache -> routing_table;
		int i = 0;
		while (entry != NULL && i++ < MAX_ROUTING_TABLE_ENTRY) {
			if (entry -> starting_eid == 0)
				return;
			if ((GET_ROUTING_ENTRY_TYPE(entry->entry_type) == MCTP_ROUTING_ENTRY_ENDPOINT  || 
					GET_ROUTING_ENTRY_TYPE(entry->entry_type) == MCTP_ROUTING_ENTRY_BRIDGE) &&
				entry->starting_eid == eid &&
				entry->phys_transport_binding_id ==
					phys_transport_binding_id) {
				*remote_id = entry->phys_address[0] << 8 |
						entry->phys_address[1];
				return;
			}
			entry = (struct get_routing_table_entry *) ((uint8_t*) entry + sizeof(struct get_routing_table_entry) - entry->phys_address_size % 2);
		}
		mctp_routing_table_cache = mctp_routing_table_cache->next;
	}
}

static mctp_routing_table_cache_t* find_routing_table_cache(mctp_eid_t eid, uint8_t media_type) {
	if (g_mctp_routing_table_cache == NULL) {
		g_mctp_routing_table_cache = malloc(sizeof(mctp_routing_table_cache_t));		
		memset(g_mctp_routing_table_cache, 0, sizeof(mctp_routing_table_cache_t));
		g_mctp_routing_table_cache -> eid = eid;
		g_mctp_routing_table_cache -> media_type = media_type;
		g_mctp_routing_table_cache ->next = NULL;
	}

	mctp_routing_table_cache_t* mctp_routing_table_cache = g_mctp_routing_table_cache;
	while (mctp_routing_table_cache != NULL) {
		if (mctp_routing_table_cache->eid == eid && mctp_routing_table_cache->media_type == media_type)
			break;

		if (mctp_routing_table_cache -> next == NULL) {
			mctp_routing_table_cache -> next = malloc(sizeof(mctp_routing_table_cache_t));		
			memset(mctp_routing_table_cache -> next , 0, sizeof(mctp_routing_table_cache_t));
			mctp_routing_table_cache -> next -> eid = eid;
			mctp_routing_table_cache -> next -> media_type = media_type;
		}
		mctp_routing_table_cache = mctp_routing_table_cache -> next;
	}
	return mctp_routing_table_cache;
}

int mctp_add_routing_table_entry(mctp_eid_t local_eid_default, mctp_eid_t eid, uint8_t status, uint8_t media_type, uint16_t phys_addr)
{
	mctp_routing_table_cache_t* mctp_routing_table_cache = find_routing_table_cache(local_eid_default, media_type);

	if (mctp_routing_table_cache == NULL)
		return -1;

	if (mctp_routing_table_cache->offset + sizeof(struct get_routing_table_entry) > sizeof(mctp_routing_table_cache->routing_table)) {
		MCTP_SYS_ERR("Error: routing table full for EID %d, media_type %d\n", local_eid_default, media_type);
		return -1;
	}

	struct get_routing_table_entry *entry = (struct get_routing_table_entry *)((uint8_t *)mctp_routing_table_cache->routing_table + mctp_routing_table_cache->offset);
	entry -> starting_eid = eid;
	entry -> eid_range_size = 1;
	(status & MCTP_SETEID_ALLOC_STATUS_EID_POOL_REQ) ?
		SET_ROUTING_ENTRY_TYPE(entry -> entry_type, MCTP_ROUTING_ENTRY_BRIDGE) : SET_ROUTING_ENTRY_TYPE(entry -> entry_type, MCTP_ROUTING_ENTRY_ENDPOINTS);
	entry -> phys_transport_binding_id = media_type;
	entry -> phys_address [0] = phys_addr >> 8;
	entry -> phys_address [1] = phys_addr;
	entry -> phys_address_size = 2;
	mctp_routing_table_cache -> offset += sizeof(struct get_routing_table_entry);
	
	return 0;
}

int mctp_add_routing_table_bridge(mctp_eid_t local_eid_default, mctp_eid_t eid, uint8_t eid_count, uint8_t media_type, uint16_t phys_addr)
{
	mctp_routing_table_cache_t* mctp_routing_table_cache = find_routing_table_cache(local_eid_default, media_type);

	if (mctp_routing_table_cache == NULL)
		return -1;

	if (mctp_routing_table_cache->offset + sizeof(struct get_routing_table_entry) > sizeof(mctp_routing_table_cache->routing_table)) {
		MCTP_SYS_ERR("Error: routing table full for EID %d, media_type %d\n", local_eid_default, media_type);
		return -1;
	}

	struct get_routing_table_entry *entry = (struct get_routing_table_entry *)((uint8_t *)mctp_routing_table_cache->routing_table + mctp_routing_table_cache->offset);
	entry -> starting_eid = eid;
	entry -> eid_range_size = eid_count;
	SET_ROUTING_ENTRY_TYPE(entry -> entry_type, MCTP_ROUTING_ENTRY_ENDPOINTS);
	entry -> phys_transport_binding_id = media_type;
	entry -> phys_address [0] = phys_addr >> 8;
	entry -> phys_address [1] = phys_addr;
	entry -> phys_address_size = 2;
	mctp_routing_table_cache -> offset += sizeof(struct get_routing_table_entry);

	return 0;
}

int mctp_write_routing_table(mctp_eid_t eid, uint8_t media_type, uint8_t handle, uint8_t * entry, int len)
{
	mctp_routing_table_cache_t* mctp_routing_table_cache = find_routing_table_cache(eid, media_type);

	if (mctp_routing_table_cache == NULL)
		return -1;

	if (mctp_routing_table_cache->offset + len > (int)sizeof(mctp_routing_table_cache->routing_table)) {
		MCTP_SYS_ERR("Error: routing table write overflow for EID %d, offset %d + len %d > %zu\n",
			eid, mctp_routing_table_cache->offset, len, sizeof(mctp_routing_table_cache->routing_table));
		return -1;
	}

	uint8_t * routing_table = mctp_routing_table_cache->routing_table;
	memcpy((uint8_t*) routing_table + mctp_routing_table_cache -> offset, entry, len);
	if (handle == 0xFF) 
		mctp_routing_table_cache -> offset = 0;
	else 
		mctp_routing_table_cache -> offset += len;
	return 0;
}

int mctp_clear_routing_table_cache()
{
	mctp_routing_table_cache_t* mctp_routing_table_cache = g_mctp_routing_table_cache;
	mctp_routing_table_cache_t* next_mctp_routing_table_cache;
	
	while(mctp_routing_table_cache != NULL) {
		next_mctp_routing_table_cache = mctp_routing_table_cache->next;
		free(mctp_routing_table_cache);
		mctp_routing_table_cache = next_mctp_routing_table_cache;
	}
	return 0;
}

void mctp_print_routing_table()
{
    mctp_routing_table_cache_t* mctp_routing_table_cache = g_mctp_routing_table_cache;
    
    MCTP_SYS_DEBUG("Routing Table Entries:\n");
    
    while (mctp_routing_table_cache != NULL) {
        struct get_routing_table_entry *entry = (struct get_routing_table_entry *) mctp_routing_table_cache->routing_table;
        int i = 0;
        
        while (entry != NULL && i++ < MAX_ROUTING_TABLE_ENTRY) {
            if (entry->starting_eid == 0)
                break;
			
			MCTP_SYS_DEBUG("  =========================================\n");
            MCTP_SYS_DEBUG("  Entry %d:\n", i);
            MCTP_SYS_DEBUG("  Starting EID: %d\n", entry->starting_eid);
            MCTP_SYS_DEBUG("  EID Range Size: %d\n", entry->eid_range_size);
            MCTP_SYS_DEBUG("  Entry Type: %d\n", GET_ROUTING_ENTRY_TYPE(entry->entry_type));
            MCTP_SYS_DEBUG("  Physical Transport Binding ID: %d\n", entry->phys_transport_binding_id);
            MCTP_SYS_DEBUG("  Physical Address: 0x%02X%02X\n", entry->phys_address[0], entry->phys_address[1]);
            MCTP_SYS_DEBUG("  Physical Address Size: %d\n", entry->phys_address_size);
			MCTP_SYS_DEBUG("  =========================================\n");
            
            entry = (struct get_routing_table_entry *) ((uint8_t*) entry + sizeof(struct get_routing_table_entry) - entry->phys_address_size % 2);
        }

        mctp_routing_table_cache = mctp_routing_table_cache->next;
    }
}

#if 0
#define FileName "/tmp/routing_table"

int mctp_write_routing_table(uint8_t * entry, int len)
{
	struct flock lock;
	lock.l_type = F_WRLCK; /* read/write (exclusive versus shared) lock */
	lock.l_whence = SEEK_SET; /* base for seek offsets */
	lock.l_start = 0; /* 1st byte in file */
	lock.l_len = 0; /* 0 here means 'until EOF' */
	lock.l_pid = getpid(); /* process id */

	int fd; /* file descriptor to identify a file within a process */
	if ((fd = open(FileName, O_RDWR | O_CREAT, 0666)) <
	    0) /* -1 signals an error */
		return -1;

	if (fcntl(fd, F_SETLK, &lock) <
	    0) /** F_SETLK doesn't block, F_SETLKW does **/
		return -1;
	else {
		int ret = write(
			fd, entry,
			len); /* populate data file */
		fprintf(stderr,
			"Process %d has written (%d) bytes to data file...\n",
			lock.l_pid, ret);
	}

	/* Now release the lock explicitly. */
	lock.l_type = F_UNLCK;
	if (fcntl(fd, F_SETLK, &lock) < 0)
		return -1;

	close(fd); /* close the file: would unlock if needed */
	return 0; /* terminating the process would unlock as well */
}

int mctp_read_routing_table()
{
	struct flock lock;
	lock.l_type = F_WRLCK; /* read/write (exclusive) lock */
	lock.l_whence = SEEK_SET; /* base for seek offsets */
	lock.l_start = 0; /* 1st byte in file */
	lock.l_len = 0; /* 0 here means 'until EOF' */
	lock.l_pid = getpid(); /* process id */

	int fd; /* file descriptor to identify a file within a process */
	if ((fd = open(FileName, O_RDONLY)) < 0) /* -1 signals an error */
		return -1;

	/* If the file is write-locked, we can't continue. */
	fcntl(fd, F_GETLK,
	      &lock); /* sets lock.l_type to F_UNLCK if no write lock */
	if (lock.l_type != F_UNLCK)
		return -1;

	lock.l_type = F_RDLCK; /* prevents any writing during the reading */
	if (fcntl(fd, F_SETLK, &lock) < 0)
		return -1;

	/* Read the bytes (they happen to be ASCII codes) one at a time. */
	int c = 0; /* buffer for read bytes */

	while ((c = read(fd, (uint8_t *)routint_table + c,
			 sizeof(routint_table))) > 0)
		; /* 0 signals EOF */

	/* Release the lock explicitly. */
	lock.l_type = F_UNLCK;
	if (fcntl(fd, F_SETLK, &lock) < 0)
		return -1;

	close(fd);
	return 0;
}

#endif