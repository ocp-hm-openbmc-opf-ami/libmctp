#include <stdio.h>
#include <stdint.h>

#include "mctp-ctrl.h"
#include "mctp-utils.h"

/*---------------------------------------------------------------------------
 * @fn onCheckInterfaceName
 *
 * @brief Handler function for setting specific mctp network interface name
 *
 * @param ifname   - mctp network interface name
 * @param bus_num  - bus number
 * @return 0 if success
 *         -1 otherwise
 *---------------------------------------------------------------------------*/

int onCheckInterfaceName(char * ifname, int *bus_num)
{
	(void)bus_num;

	printf("onCheckInterfaceName called %s\n", ifname);
	if(strcmp(ifname, "mctpi2c0") == 0){
		printf("Set ifname for mbox0 !\n");
		sprintf(ifname, "mctpmbox%d", 0);
	}
	return 0;
}
