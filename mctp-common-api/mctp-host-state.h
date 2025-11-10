#ifndef __MCTP_HOST_STATE_H__
#define __MCTP_HOST_STATE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "mctp-ctrl.h"

int mctp_detect_power_state();
int mctp_detect_host_reset();
int registerHostMatch(sd_bus *bus);
int registerPowerMatch(sd_bus *bus);
int registerOemMatch(sd_bus *bus);
int mctp_register_host_state_signal(sd_bus *bus);
int mctp_check_host_reset_event();
int mctp_deregister_host_state_signal();
int mctp_ctrl_handle_host_reset(mctp_ctrl_t *mctp_ctrl);

#ifdef __cplusplus
}
#endif
#endif
