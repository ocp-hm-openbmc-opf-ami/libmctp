#include <stdio.h>
#include <stdint.h>

#include "mctp-ctrl.h"
#include "mctp-utils.h"
#include <sys/ioctl.h>
#include <errno.h>
#define SIOCMCTPSETFLOWTO	(SIOCPROTOPRIVATE + 2)
struct mctp_ioc_flow_ctl {
	unsigned int	flow_timeout_ms;
};
const unsigned int MCTPControlMT2TimeoutInMilliseconds = 300;

/*---------------------------------------------------------------------------
 * @fn onI2CInit
 *
 * @brief Handler function for extra process in MCTP over I2C initialization
 *
 * @param cmd  	 - mctp_cmdline_args_t *
 * @param ctrl   - mctp_ctrl_t *
 * @return 0 if success
 *         -1 otherwise
 *---------------------------------------------------------------------------*/
int onI2CInit(const mctp_cmdline_args_t *cmd, mctp_ctrl_t *ctrl)
{
	(void)cmd;
    printf("%s: setting flow timeout\n", __func__);
	struct mctp_ioc_flow_ctl ctl = { 0 };
	int rc;

	ctl.flow_timeout_ms = MCTPControlMT2TimeoutInMilliseconds;

	rc = ioctl(ctrl->sock, SIOCMCTPSETFLOWTO, &ctl);
	if (0 != rc) {
		printf("Error setting flow timeout: %s", strerror(errno));
		return -errno;
	}
	return 0;
}
