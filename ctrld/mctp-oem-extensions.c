#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <dirent.h>
#include "mctp-oem-extensions.h"
#include <string.h>
#include "mctp-ctrl-log.h"
#include <unistd.h>
#include <fcntl.h>

pfunc g_OEMMCTPHndlr[MAX_MCTP_OEM_HANDLE];
void *dl_oemmctphndlr;

OEM_MCTPInit g_OEMMCTPInitialize[] = 
{
    { ON_PCIE_DISCOVERY, "onPCIeDiscovery" }
};

int get_hardware_id_config(char *line, int size)
{
	// Create a file pointer and open the file "GFG.txt" in
	// read mode.
	int file = open("/usr/share/mctp/mctp_hardware_id", O_RDONLY);

	// Check if the file was opened successfully.
	if (file >= 0) {
		// Read each line from the file and store it in the
		// 'line' buffer.
		int bytes = read(file, line, size);
		// Close the file stream once all lines have been
		// read.
		close(file);
		return bytes;

	} else {
		// Print an error message to the standard error
		// stream if the file cannot be opened.
		MCTP_CTRL_ERR("Unable to open get_hardware_id_config!\n");
		return -1;
	}

	return 0;
}

int scan_oem_lib(char *mctp_oem_path, int lenth)
{
	DIR *dir;
	struct dirent *ptr;
	int ret = EXIT_FAILURE;

	if (access(MCTPOEM_LIB, F_OK) == 0) {
		snprintf(mctp_oem_path, lenth, MCTPOEM_LIB);
		MCTP_CTRL_DEBUG("init_oem_pdk_hook: %s\n", mctp_oem_path);
		return EXIT_SUCCESS;
	}

	if ((dir = opendir("/usr/lib")) == NULL) {
		MCTP_CTRL_ERR("opendir (/usr/lib) failed!");
		return EXIT_FAILURE;
	}

	while ((ptr = readdir(dir)) != NULL) {
		if (strncmp(ptr->d_name, "libmctp_PDK_", 12) == 0) {
			snprintf(mctp_oem_path, lenth, "/usr/lib/%s", ptr->d_name);
			MCTP_CTRL_DEBUG("init_oem_pdk_hook: %s\n", mctp_oem_path);
			ret = EXIT_SUCCESS;
			break;
		}
	}

	closedir(dir);
	return ret;
}

/*
 *@fn init_oem_pdk_hook
 *@brief Initializes Handles for libmctp OEM library
 *@return Returns 0 on success
 *        Returns -1 on failure
 */
int init_oem_pdk_hook()
{
	unsigned int i = 0;
	char mctp_oem_path[128];

	if (scan_oem_lib(mctp_oem_path, sizeof(mctp_oem_path)) != EXIT_SUCCESS) 
		return EXIT_FAILURE;

	dl_oemmctphndlr = dlopen(mctp_oem_path, RTLD_LAZY);
	if (!dl_oemmctphndlr) {
		MCTP_CTRL_ERR(
			"MCTP ERROR: Error in loading MCTP OEM library %s %s\n",
			mctp_oem_path, dlerror());
		return -1;
	}

// Use a GCC-specific pragma to suppress warnings
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	for (i = 0;
	     i < sizeof(g_OEMMCTPInitialize) / sizeof(g_OEMMCTPInitialize[0]);
	     i++) {
		int (*function1)(void *, void *) =
			(int (*)(void *, void *))dlsym(
				dl_oemmctphndlr,
				(char *)g_OEMMCTPInitialize[i].OEMHookName);
		g_OEMMCTPHndlr[g_OEMMCTPInitialize[i].OEMHookNum] = function1;
	}
#pragma GCC diagnostic pop

	return 0;
}
