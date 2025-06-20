
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
