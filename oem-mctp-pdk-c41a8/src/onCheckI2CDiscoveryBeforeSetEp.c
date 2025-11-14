#include <stdio.h>
#include <stdint.h>

#include "mctp-ctrl.h"
#include "mctp-utils.h"
#include "mctp-netlink.h"

/*---------------------------------------------------------------------------
 * @fn onCheckI2CDiscoveryBeforeSetEp
 *
 * @brief Handler function for checking customize option before MCTP I2C discovery set endpoint
 * 
 * @param ifname  	 - mctp network interface name *
 * @param slave_addr - slave address *
 * @return 0 if success
 * 	   	  -1 if  otherwise
 *---------------------------------------------------------------------------*/
int onCheckI2CDiscoveryBeforeSetEp(uint8_t* eid, uint8_t* slave_addr)
{
    (void)slave_addr;
	if (mctp_nl_add_route(*eid) < 0) {
		printf("%s: Failed to add route for eid %d\n", __func__,
		    *eid);
            return -1;
	}

	if (mctp_nl_add_neigh(*eid) < 0) {
		printf("%s: Failed to add neigh for eid %d\n", __func__,
			*eid);
        return -1;
	}
	return 0;
}