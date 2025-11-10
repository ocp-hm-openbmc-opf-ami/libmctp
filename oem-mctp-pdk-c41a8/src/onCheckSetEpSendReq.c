#include <stdio.h>
#include <stdint.h>

#include "mctp-ctrl.h"
#include "mctp-utils.h"

/*---------------------------------------------------------------------------
 * @fn onCheckSetEpSendReq
 *
 * @brief Handler function check if tthe device has customize requirement with MCTP_SET_EP_REQUEST
 * 
 * @param bus_num  	 - bus number *
 * @param slave_addr - slave address *
 * @return 0 if not send eid with MCTP_SET_EP_REQUEST
 * 	   	   1 if send eid with MCTP_SET_EP_REQUEST
 *---------------------------------------------------------------------------*/
int onCheckSetEpSendReq(uint8_t* bus_num, uint8_t* slave_addr)
{
    printf("onCheckSetEpSendReq called, bus_num: %d, slave_addr: %d\n", *bus_num, *slave_addr);
    if(*bus_num == 20){
        if(*slave_addr == 0x53 || *slave_addr == 0x58 || *slave_addr == 0x73){
            printf("onCheckSetEpSendReq: Setting EID for bus_num: %d, slave_addr: %d\n", *bus_num, *slave_addr);
            return 1;
        }
    }
	return 0;
}
