#ifndef __MCTP_EXT_SDBUS_H__
#define __MCTP_EXT_SDBUS_H__

#ifdef __cplusplus
extern "C" {
#endif
bool check_endpoint_discovered(uint8_t eid);
int mctp_ctrl_sdbus_object_remove_all_signal(sd_bus *bus);
int mctp_ctrl_sdbus_object_remove_eid(sd_bus *bus, mctp_eid_t eid);
int mctp_ctrl_sdbus_object_remove_invalid_eid(sd_bus *bus);

#ifdef __cplusplus
}
#endif
#endif
