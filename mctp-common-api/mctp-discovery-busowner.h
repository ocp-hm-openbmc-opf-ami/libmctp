/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef __MCTP_DISCOVERY_BUSOWNER_H__
#define __MCTP_DISCOVERY_BUSOWNER_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "mctp-ctrl.h"
#include "mctp-ctrl-cmdline.h"
#include "mctp-ctrl-cmds.h"
#include "mctp-discovery-common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes */


mctp_ret_codes_t mctp_busowner_mode_discover_endpoints(const mctp_cmdline_args_t *cmd,
					 mctp_ctrl_t *ctrl);
mctp_ret_codes_t mctp_busowner_mode_ctrl_cmd_responder(mctp_ctrl_t *ctrl,
					       mctp_binding_ids_t bind_id,
						   mctp_eid_t eid,
					       uint8_t **mctp_resp_msg,
					       size_t *mctp_resp_len,
					       uint8_t **mctp_hdr_msg);

void mctp_busowner_reset_discovery_state();

#ifdef __cplusplus
}
#endif

#endif /* __MCTP_DISCOVERY_BUSOWNER_H__ */
