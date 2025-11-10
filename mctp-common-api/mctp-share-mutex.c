#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <pthread.h>
#include "libmctp.h"
#include "mctp-utils.h"
#include <errno.h>
#include <string.h>


#define SHM_NAME "/mctp_shared_memory_i2c"

typedef struct {
	pthread_mutex_t mutex;
	int data;
} shared_data_t;

shared_data_t *shared = NULL;
int shm_fd = 0;

int i2c_mutex_open(int bus_num)
{
	(void)bus_num;
	
#ifndef MCTP_IN_KERNEL	
	char shm_file_name[256] = { 0 };
	snprintf(shm_file_name, sizeof(shm_file_name), "%s%d", SHM_NAME,
		 bus_num);
	shm_fd = shm_open(shm_file_name, O_RDWR, 0666);
	if (shm_fd == -1) {
		MCTP_SYS_ERR("i2c_mutex_open shm_fd:  %d (%s)\n",
			errno, strerror(errno));
		return -1;
	}

	shared = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE,
		      MAP_SHARED, shm_fd, 0);
	if (shared == MAP_FAILED) {
		MCTP_SYS_ERR("i2c_mutex_open mmap:  %d (%s)\n",
			errno, strerror(errno));
		return -1;
	}
#endif	
	return 0;
}

int i2c_mutex_close()
{
#ifndef MCTP_IN_KERNEL	
	if (shared != NULL) {
		munmap(shared, sizeof(shared_data_t));
		close(shm_fd);
		shared = NULL;
	}
#endif	
	return 0;
}

int i2c_mutex_create(int bus_num)
{
	(void)bus_num;

#ifndef MCTP_IN_KERNEL
	char shm_file_name[256] = { 0 };
	snprintf(shm_file_name, sizeof(shm_file_name), "%s%d", SHM_NAME,
		 bus_num);
	shm_fd = shm_open(shm_file_name, O_CREAT | O_RDWR, 0666);
	if (shm_fd == -1) {
		MCTP_SYS_ERR("i2c_mutex_open shm_fd: %d (%s)\n",
			errno, strerror(errno));
		return -1;
	}

	int ret = ftruncate(shm_fd, sizeof(shared_data_t));
	if (ret != 0) {
		MCTP_SYS_ERR("ftruncate error  %d (%s)\n",
			errno, strerror(errno));
	}
	shared = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE,
		      MAP_SHARED, shm_fd, 0);
	if (shared == MAP_FAILED) {
		MCTP_SYS_ERR("mmap:  %d (%s)\n",
			errno, strerror(errno));
		return -1;
	}

	// Initialize the mutex
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&shared->mutex, &attr);
	pthread_mutexattr_destroy(&attr);
#endif
	return 0;
}

int i2c_mutex_lock()
{
#ifndef MCTP_IN_KERNEL
	if (shared == NULL) {
		MCTP_SYS_ERR("i2c_mutex_lock shared: %d (%s)\n",
			errno, strerror(errno));
		return -1;
	}
	pthread_mutex_lock(&shared->mutex);
#endif	
	return 0;
}

int i2c_mutex_unlock()
{
#ifndef MCTP_IN_KERNEL
	if (shared == NULL) {
		MCTP_SYS_ERR("i2c_mutex_unlock shared:  %d (%s)\n",
			errno, strerror(errno));
		return -1;
	}
	pthread_mutex_unlock(&shared->mutex);
#endif
	return 0;
}
