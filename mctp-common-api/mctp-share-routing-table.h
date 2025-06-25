
#ifndef __MCTP_SHARE_ROUTING_TABLE__
#define __MCTP_SHARE_ROUTING_TABLE__
#include "ctrld/mctp-ctrl-cmds.h"
#ifdef __cplusplus
extern "C" {
#endif
void mctp_get_routing_table_entry_remote_id(mctp_eid_t eid, uint16_t* remote_id, uint8_t phys_transport_binding_id);
int mctp_write_routing_table(mctp_eid_t eid, uint8_t media_type, uint8_t handle, uint8_t * entry, int len);
int mctp_add_routing_table_entry(mctp_eid_t local_eid_default, mctp_eid_t eid, uint8_t status, uint8_t media_type, uint16_t phys_addr);
int mctp_add_routing_table_bridge(mctp_eid_t local_eid_default, mctp_eid_t eid, uint8_t eid_count, uint8_t media_type, uint16_t phys_addr);
int mctp_clear_routing_table_cache();
void mctp_print_routing_table();

#ifdef __cplusplus
}
#endif

#endif