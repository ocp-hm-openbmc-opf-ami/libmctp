
#ifndef __MCTPPDKACCESS_H__
#define __MCTPPDKACCESS_H__
#include <stdint.h> // For uintptr_t

#ifdef __cplusplus
extern "C" {
#endif

#define MCTPOEM_LIB "/usr/lib/libmctp_PDK_extensions.so.1"

typedef enum {
	ON_PCIE_DISCOVERY = 0,
	ON_I2C_DISCOVERY,
	ON_CHECK_INTERFACE_NAME,
	ON_CHECK_CLIENT_WITH_BINDING_SEND,
	ON_I2C_INIT,
	ON_DETECT_HOT_PLUG,
	ON_CLIENT_SEND_EXT,
	ON_CHECK_SET_EP_SEND_REQ,
	ON_CHECK_I2C_DISCOVERY_BEFORE_SET_EP,
	MAX_MCTP_OEM_HANDLE
} OEM_MCTPHooks;

typedef struct {
	unsigned short OEMHookNum;
	unsigned char OEMHookName[128];
} OEM_MCTPInit;

typedef int (*pfunc)(void *, void *);

extern pfunc g_OEMMCTPHndlr[MAX_MCTP_OEM_HANDLE];
extern void *dl_oemmctphndlr;

extern int init_oem_pdk_hook();

#ifdef __cplusplus
}
#endif
#endif
