#include <stdio.h>
#include <stdint.h>
#include <linux/mctp.h>

#include "mctp-ctrl.h"
#include "mctp-utils.h"

#define MCTP_SKB_FLAGS_QUEUE_READ	(1<<0)
#define MCTP_SKB_FLAGS_FORCE_READ	(1<<1)
#define MCTP_SKB_FLAGS_RETURN_TAG	(1<<2)
#define MCTP_SKB_FLAGS_NO_MUX_HOLD	(1<<3)

/*---------------------------------------------------------------------------
 * @fn onClientSendExt
 *
 * @brief Handler function for setting customize option in mctp_client_send_ext
 * 
 * @param ifname  	 - mctp network interface name *
 * @param addr       - sockaddr_mctp_ext struct *
 * @return 0 if  send via mctp_client_send_ext
 *---------------------------------------------------------------------------*/
int onClientSendExt(char* ifname, struct sockaddr_mctp_ext* addr)
{
    if (strcmp(ifname, "mctpi2c20") == 0) {
		// bypass holding the MUX open for target-only devices
		addr->__smctp_pad0[2] = MCTP_SKB_FLAGS_NO_MUX_HOLD;

		addr->__smctp_pad0[2] |= MCTP_SKB_FLAGS_QUEUE_READ;
		
	}

    return 0;
}
