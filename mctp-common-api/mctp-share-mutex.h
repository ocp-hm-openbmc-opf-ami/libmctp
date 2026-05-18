
#ifndef __MCTP_SHARE_MUTEX_TABLE__
#define __MCTP_SHARE_MUTEX_TABLE__
#include "ctrld/mctp-ctrl-cmds.h"
#ifdef __cplusplus
extern "C" {
#endif

int i2c_mutex_create(int bus_num);
int i2c_mutex_close();
int i2c_mutex_open(int bus_num);
// timeout_ms < 0 means block indefinitely
int i2c_mutex_lock(int timeout_ms);
int i2c_mutex_unlock();

#ifdef __cplusplus
}
#endif

#endif