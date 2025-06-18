#include <stdio.h>
#include <stdint.h>

#include "mctp-ctrl.h"
#include "mctp-utils.h"
#include "mctp-discovery-busowner.h"

/*---------------------------------------------------------------------------
 * @fn onPCIeDiscovery
 *
 * @brief Handler function for MCTP over I2C Discovery end event
 * 
 * @param cmd  	 - mctp_cmdline_args_t *
 * @param ctrl   - mctp_ctrl_t *
 * @return 0 if success
 *         -1 otherwise
 *---------------------------------------------------------------------------*/
int onPCIeDiscovery(const mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl)
{
    // add your oem implementation here	
	return mctp_busowner_mode_discover_endpoints((const mctp_cmdline_args_t *)cmd,
					 (mctp_ctrl_t *)ctrl);
}
