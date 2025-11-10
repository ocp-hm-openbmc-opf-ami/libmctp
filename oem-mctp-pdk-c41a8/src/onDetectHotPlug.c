#include <stdio.h>
#include <stdint.h>

#include "mctp-ctrl.h"
#include "mctp-utils.h"
#include "mctp-discovery-busowner.h"

/*---------------------------------------------------------------------------
 * @fn onDetectHotPlug
 *
 * @brief Handler function for checking to detect hot plug detection
 * 
 * @param bus_num  	 - bus number *
 * @param slave_addr - slave address *
 * @return 1 for skip hot plug detection
 *---------------------------------------------------------------------------*/
int onDetectHotPlug(int* bus_num, int* slave_addr)
{
    printf("onDetectHotPlug called, bus_num: %d, slave_addr: %d\n", *bus_num, *slave_addr);
	return 1;
}
