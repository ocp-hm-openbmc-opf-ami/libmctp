#include <stdio.h>
#include <stdint.h>

#include "mctp-ctrl.h"
#include "mctp-utils.h"

/*---------------------------------------------------------------------------
 * @fn onCheckClientWithBindingSend
 *
 * @brief Handler function for checking the customize option in  mctp_client_with_binding_send
 * 
 * @param ifname  	 - mctp network interface name *
 * @param slave_addr - slave address *
 * @return 0 if not send via mctp_client_send_ext
 * 	   	   1 if send via mctp_client_send_ext
 *---------------------------------------------------------------------------*/

int onCheckClientWithBindingSend(char* ifname, int* slave_addr)
{
	if(strcmp(ifname, "mctpi2c20") == 0){
		printf("Checking ifname for i2c20 !\n");
		if(*slave_addr == 0x53 || *slave_addr == 0x58 || *slave_addr == 0x73){
			return 1;
		}
	}
	return 0;
}
