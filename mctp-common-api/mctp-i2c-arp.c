#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define pr_fmt(x) "smbus: " x

#ifdef MCTP_HAVE_CONFIG_H
#include "config.h"
#endif

#include <i2c/smbus.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>

#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"
#include "libmctp.h"
#include "mctp-json.h"
#include <dirent.h>
#include "mctp-share-mutex.h"
#include "mctp-i2c-arp.h"
#include "mctp-utils.h"


struct mctp_binding_smbus {
	struct mctp_binding binding;
	int out_fd[MCTP_I2C_MAX_BUSES];
	int in_fd;
	unsigned long bus_id;

	/* receive buffer */
	uint8_t rxbuf[1024];
	struct mctp_pktbuf *rx_pkt;
	/* temporary transmit buffer */
	uint8_t txbuf[256];

	/* bus number */
	uint8_t bus_num[MCTP_I2C_MAX_BUSES];
	/* bus number */
	uint8_t bus_num_smq;
	/* dest slave address */
	uint8_t dest_slave_addr[MCTP_I2C_MAX_BUSES];
	/* src slave address */
	uint8_t src_slave_addr;
	/* chosen_eid_type*/
	uint8_t chosen_eid_type;
	/* tx bus number*/
	uint8_t tx_bus_num;

	/* static endpoints configuration */
	struct mctp_static_endpoint_mapper *static_endpoints;
	uint8_t static_endpoints_len;
};

// SMB 2.0 ARP Command Definitions
#define RESERVED_ARP_COMMAND 0x00
#define PREPARE_ARP_COMMAND  0x01
#define PREPARE_ARP_LEN	     0x01
#define RESET_DEV_COMMAND    0x02
#define RESET_DEV_LEN	     0x01
#define GENERAL_COMMAND	     0x03
#define DIRECTED_COMMAND     0x01
#define SET_ADDR_COMMAND     0x04

/* i2c_smbus_xfer read or write markers */
#define I2C_SMBUS_READ	1
#define I2C_SMBUS_WRITE 0

#define UDID_STR_LEN 16

#define MAX_I2C_BUS_NUM	     16
#define ARP_ADDRESS_RESERVED 0
#define ARP_USED_BY_DEVICE   1

#define BASE_SLAVE_SET_ADDR 0x12
#define SLAVE_BUS	    "/dev/i2c"
#define MAX_I2C_BUS_LEN	    16

// Legal values in the range 0x10 to 0x7E, can be used for assignment
// The total addr count is 110, and the first addr 0x10 is reserved for IPMI BMC address so deduct one
#define MAX_LEGAL_ADDR_COUNT 109
unsigned char used_address_pool[MAX_LEGAL_ADDR_COUNT];

// Assigned SMBus address
#define SMBUS_HOST	       0x08
#define SMART_BATTERY_CHARGER  0x09
#define SMART_BATTERY_SELECTOR 0x0a
#define SMART_BATTERY	       0x0b
#define SMBUS_ALERT	       0x0c
#define ACCESS_BUS_HOST	       0x28
#define RESERVED_LCD	       0x2c
#define RESERVED_CCFL	       0x2d
#define ACCESS_BUS_DEFAULT     0x37
#define RESERVED_PCMCIA_1      0x40
#define RESERVED_PCMCIA_2      0x41
#define RESERVED_PCMCIA_3      0x42
#define RESERVED_PCMCIA_4      0x43
#define RESERVED_VGA	       0x44
#define UNRESTRICTED_1	       0x48
#define UNRESTRICTED_2	       0x49
#define UNRESTRICTED_3	       0x4a
#define UNRESTRICTED_4	       0x4b
#define SMBUS_DEV_DEFAULT_ADDR 0x61

// SMB 2.0 UDID Command Definitions
#define GET_UDID_DATA_SIZE 0x11
#define BYTE0_DATALEN	   0
#define BYTE1_CAPABILITIES 1
#define BYTE3_4_VENDORID   3
#define BYTE5_6_DEVICEID   5
#define BYTE8_ASF_BIT	   8
#define BYTE17_SLAVE_ADDR  17
#define ASF_MCTP_BITMASK                                                       \
	0x20 // This value of Bit5 = 1 is for MCTP Support as per Intel I350 Spec Pg 814
#define ARP_FIXED_ADDR	    0x00
#define ARP_DYNC_PERSISTENT 0x01
#define ARP_DYNC_VOLATILE   0x10
#define ARP_RANDOM_DEV	    0x11
#define GET_ADDR_TYPE(X)                                                       \
	((X >> 6) & 0x3) // The address type are the first two bits presented
#define START_SEARCH_ADDR 0x08
#define END_SEARCH_ADDR	  0x77
#define UDID_START_POS	  1

/* Default smbus slave address for get UDID command */
#define MCTP_SMBUS_DEFAULT_GET_UDID_SLAVE_ADDRESS 0x61

int mctp_smbus_open_out_bus(struct mctp_binding_smbus *smbus, int out_bus)
{
	(void)smbus;

#if USE_MOCKED_DRIVERS
// Fuzz tests and UT require mocked smbus driver,
// this is instead of an mqueue or any other standard i2c
#define SMBUS_MOCKED_DRIVER "/dev/smbus"

	MCTP_SYS_DEBUG("%s: Open: %s, out bus = %d\n", __func__,
		     SMBUS_MOCKED_DRIVER, out_bus);
	int outfd =
		open(SMBUS_MOCKED_DRIVER, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	MCTP_SYS_DEBUG("%s: ret = : %d\n", __func__, outfd);
	MCTP_ASSERT_RET(outfd >= 0, -1, "Failed to open I2C Tx node: %d",
			outfd);
	return outfd;
#else
	char filename[60];
	size_t size = sizeof(filename);

	snprintf(filename, size, "/dev/i2c-%d", out_bus);
	filename[size - 1] = '\0';

	MCTP_SYS_DEBUG("%s: open file: %s\n", __func__, filename);
	return open(filename, O_RDWR | O_NONBLOCK);
#endif
}

int i2c_smbus_arp_init(int file)
{
	int ret = 0;

	//Set remote slave
	if (ioctl(file, I2C_SLAVE, SMBUS_DEV_DEFAULT_ADDR) < 0) {
		MCTP_SYS_ERR("Cannot set remote slave device for master write");
		return -1;
	}

	/* Set PEC*/
	if (ioctl(file, I2C_PEC, 1) < 0) {
		MCTP_SYS_ERR("Cannot set pec for master write");
		return -1;
	}

	ret = i2c_smbus_access(file, I2C_SMBUS_WRITE, PREPARE_ARP_COMMAND, 1,
			       NULL);
	if (ret != 1)
		return ret;

	int retry = 2;
	while (retry-- > 0) {
		ret = i2c_smbus_access(file, I2C_SMBUS_WRITE, RESET_DEV_COMMAND,
				       1, NULL);
		if (ret == 1)
			break;
	}
	return ret;
}

int i2c_smbus_detect_device(int file, uint8_t slave_addr)
{
	if (ioctl(file, I2C_SLAVE_FORCE, slave_addr) < 0) {
		return -1;
	}
	char buffer[10] = { 0 };
	return write(file, buffer, 0);
}

static __s32 smbus_write_block_data(int file, __u8 command, __u8 length,
				    __u8 *values)
{
	union i2c_smbus_data data;
	int i;
	//Set remote slave
	if (ioctl(file, I2C_SLAVE, SMBUS_DEV_DEFAULT_ADDR) < 0) {
		MCTP_SYS_ERR("Cannot set remote slave device for master write");
		return -1;
	}

	/* Set PEC*/
	if (ioctl(file, I2C_PEC, 1) < 0) {
		MCTP_SYS_ERR("Cannot set pec for master write");
		return -1;
	}
	for (i = 1; i <= length; i++) {
		/* Reason for false positive - Checked the length for Out-of-bounds write */
		/* coverity[overrun-local : FALSE] */
		data.block[i] = values[i - 1];
	}

	data.block[0] = length;
	int ret = i2c_smbus_access(file, I2C_SMBUS_WRITE, command,
				   I2C_SMBUS_BLOCK_DATA, &data);
	MCTP_ASSERT_RET(ret == 0, ret, "Invalid ioctl ret val: %d (%s)", errno,
			strerror(errno));
	return ret;
}

void initial_i2c_address_pool()
{
	// Clear the I2C used address pool
	memset(used_address_pool, ARP_ADDRESS_RESERVED,
	       sizeof(used_address_pool));

	used_address_pool[ACCESS_BUS_HOST - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[RESERVED_LCD - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[RESERVED_CCFL - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[ACCESS_BUS_DEFAULT - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[RESERVED_PCMCIA_1 - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[RESERVED_PCMCIA_2 - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[RESERVED_PCMCIA_3 - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[RESERVED_PCMCIA_4 - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[RESERVED_VGA - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[UNRESTRICTED_1 - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[UNRESTRICTED_2 - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[UNRESTRICTED_3 - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[UNRESTRICTED_4 - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
	used_address_pool[SMBUS_DEV_DEFAULT_ADDR - BASE_SLAVE_SET_ADDR] =
		ARP_USED_BY_DEVICE;
}

void set_address_pool(unsigned char Addr)
{
	if (Addr >= BASE_SLAVE_SET_ADDR)
		used_address_pool[Addr - BASE_SLAVE_SET_ADDR] =
			ARP_USED_BY_DEVICE;
}

void clear_address_pool(unsigned char Addr)
{
	if (Addr >= BASE_SLAVE_SET_ADDR)
		used_address_pool[Addr - BASE_SLAVE_SET_ADDR] =
			ARP_ADDRESS_RESERVED;
}

uint8_t find_free_slave_address(int i2cfd, uint8_t slave_addr)
{
	int offset = 1;
	int retval = 0;

	while (offset < MAX_LEGAL_ADDR_COUNT) {
		if (used_address_pool[offset] == ARP_ADDRESS_RESERVED) {
			retval = i2c_smbus_detect_device(
				i2cfd, BASE_SLAVE_SET_ADDR + offset);
			if (retval >= 0 &&
			    BASE_SLAVE_SET_ADDR + offset != slave_addr) {
				// The device exists for this address, find next free
				offset++;
			} else {
				// The legal values for assign address are in the range 0010 000 to 1111 110
				// We start from 0010 001 and increased by offset
				return BASE_SLAVE_SET_ADDR + offset;
			}
		} else
			offset++;
	}

	return 0;
}

int send_direct_get_udid_command(int32_t out_fd, size_t idx, uint8_t *inbuf,
				 uint8_t len, uint8_t command)
{
	(void)idx;
	int rc;
	uint8_t outbuf[1] = { command }; // Set 'Get UDID' command
	struct i2c_msg msgs[2];
	struct i2c_rdwr_ioctl_data msgset[1];
	int slave_addr = MCTP_SMBUS_DEFAULT_GET_UDID_SLAVE_ADDRESS;

	/* Prepare message to send Get UDID */
	msgs[0].addr = slave_addr;
	msgs[0].flags = 0;
	msgs[0].len = 1;
	msgs[0].buf = outbuf;

	msgs[1].addr = slave_addr;
	msgs[1].flags = I2C_M_RD | I2C_M_NOSTART;
	msgs[1].len = len;
	msgs[1].buf = inbuf;

	msgset[0].msgs = msgs;
	msgset[0].nmsgs = 2;

	rc = ioctl(out_fd, I2C_RDWR, &msgset);
	if (rc < 0) {
		MCTP_SYS_DEBUG("%s Invalid ioctl ret val: %d (%s)", __func__, errno,
			 strerror(errno));
		return EXIT_FAILURE;
	}

	MCTP_SYS_DEBUG("%s: TX and RX Direct Get UDID command", __func__);
	/* Reason for false positive - Checked the length for Out-of-bounds write */
	/* coverity[overrun-buffer-val : FALSE] */
	mctp_trace_tx(outbuf, msgs[0].len, 0);
	mctp_trace_rx(inbuf, msgs[1].len, 0);

	return EXIT_SUCCESS;
}

int i2c_smbus_scan_dir(char *parent_dir, uint8_t bus_num, uint8_t *endpoints,
		       uint8_t *pool_of_endpoints)
{
	DIR *dir;
	struct dirent *ptr;
	char *endptr;
	char childBusPath[256] = { 0 };

	if ((dir = opendir(parent_dir)) == NULL) {
		MCTP_SYS_ERR("opendir(%s) failed!", parent_dir);
		return EXIT_FAILURE;
	}

	while ((ptr = readdir(dir)) != NULL) {
		if (strncmp(ptr->d_name, "i2c-", 4) == 0) {
			uint8_t num =
				(uint8_t)strtoul(ptr->d_name + 4, &endptr, 10);
			if (num > bus_num) {
				endpoints[(*pool_of_endpoints)++] = num;
				snprintf(childBusPath, sizeof(childBusPath),
					 "%s/%s", parent_dir, ptr->d_name);
				i2c_smbus_scan_dir(childBusPath, num, endpoints,
						   pool_of_endpoints);
			}
		}
	}

	closedir(dir);
	return 0;
}

int i2c_smbus_scan(uint8_t bus_num,
		   struct mctp_static_endpoint_mapper **static_endpoints_tab,
		   uint8_t *static_endpoints_len)
{
	uint8_t endpoints[MCTP_I2C_MAX_BUSES];
	uint8_t pool_of_endpoints = 0;
	char root_bus_path[256];

	snprintf(root_bus_path, sizeof(root_bus_path),
		 "/sys/bus/i2c/devices/i2c-%d", bus_num);
	i2c_smbus_scan_dir(root_bus_path, bus_num, endpoints,
			   &pool_of_endpoints);

	*static_endpoints_len = (uint8_t)pool_of_endpoints + 1;

	*static_endpoints_tab = (struct mctp_static_endpoint_mapper *)malloc(
		*static_endpoints_len *
		sizeof(struct mctp_static_endpoint_mapper));
	if (*static_endpoints_tab == NULL) {
		MCTP_SYS_ERR("malloc static endpoints failed!");
		return EXIT_FAILURE;
	}

	// Add root bus for access
	(*static_endpoints_tab)[0].bus_num = bus_num;
	(*static_endpoints_tab)[0].slave_address = 0;
	(*static_endpoints_tab)[0].support_mctp = 0;
	(*static_endpoints_tab)[0].endpoint_num = -1;
	for (int l = 0; l < 16; l++) {
		(*static_endpoints_tab)[0].udid[l] = 0;
	}

	for (int k = 0; k < pool_of_endpoints; k++) {
		// Initial default values
		(*static_endpoints_tab)[k + 1].bus_num = endpoints[k];
		(*static_endpoints_tab)[k + 1].slave_address = 0;
		(*static_endpoints_tab)[k + 1].support_mctp = 0;
		(*static_endpoints_tab)[k + 1].endpoint_num = -1;
		for (int l = 0; l < 16; l++) {
			(*static_endpoints_tab)[k + 1].udid[l] = 0;
		}
	}

	return EXIT_SUCCESS;
}

uint8_t i2c_bus_scan_address(int32_t out_fd, uint8_t start_addr)
{
	(void)start_addr;
	uint8_t slave_addr;
	uint8_t target_slave_address[] = { 0x32 };

	for(u_int32_t i = 0; i < sizeof(target_slave_address); i++) {
		
		slave_addr = target_slave_address[i];

		if (ioctl(out_fd, I2C_SLAVE, slave_addr) < 0) {
			continue;
		}

		if ((slave_addr >= 0x30 && slave_addr <= 0x37) /*||
		    (slave_addr >= 0x50 && slave_addr <= 0x5F)*/) {
			// EEPROM address range. Use read to detect
			if (i2c_smbus_read_byte(out_fd) < 0) {
				continue;
			} else {
				return slave_addr;
			}
		} else {
			if (i2c_smbus_write_quick(out_fd, I2C_SMBUS_WRITE) <
			    0) {
				continue;
			} else {
				return slave_addr;
			}
		}
	}
	return 0;
}

int i2c_bus_reset_device(int bus_num, u_int8_t slave_addr)
{
	int ret = 0;

	i2c_mutex_lock();

	int out_fd = mctp_smbus_open_out_bus(NULL, bus_num);

	if (out_fd < 0) {
		MCTP_SYS_ERR("i2c_bus_reset_device out_fd <0");
		i2c_mutex_unlock();
		return -1;
	}

	if (i2c_smbus_detect_device(out_fd, slave_addr) >= 0) {
		MCTP_SYS_DEBUG("i2c_smbus_detect_device success\n");
		close(out_fd);
		i2c_mutex_unlock();
		return 1;
	}

	if (ioctl(out_fd, I2C_SLAVE, SMBUS_DEV_DEFAULT_ADDR) < 0) {
		MCTP_SYS_ERR("Cannot set I2C_SLAVE for master write");
		close(out_fd);
		i2c_mutex_unlock();
		return -1;
	}
	/* Set PEC*/
	if (ioctl(out_fd, I2C_PEC, 1) < 0) {
		MCTP_SYS_ERR("Cannot set pec for master write");
		close(out_fd);
		i2c_mutex_unlock();
		return -1;
	}

	ret = i2c_smbus_access(out_fd, I2C_SMBUS_WRITE, ((slave_addr << 1) | 0),
			       I2C_SMBUS_BYTE, NULL);
	MCTP_SYS_DEBUG("i2c_bus_reset_device: %d\n", ret);

	close(out_fd);
	i2c_mutex_unlock();
	return -1;
}

int set_pool_of_endpoints(int32_t bus_num, uint8_t *target_address,
			  bool daemon_mode)
{
	uint8_t inbuf[20] = { 0 };
	uint8_t inbuf_len = 19;
	//uint8_t quantity_of_udid = 1; //at the moment only one CX7 card
	uint8_t slave_address = *target_address;

	i2c_mutex_lock();

	int out_fd = mctp_smbus_open_out_bus(NULL, bus_num);
	if (out_fd < 0) {
		MCTP_SYS_ERR("mctp_smbus_open_out_bus fail!\n");
		i2c_mutex_unlock();
		return EXIT_FAILURE;
	}

	//for(int k = 0;k< cmdline->dest_eid_tab_len; k++)
	{
		if (slave_address == 0) {
			MCTP_SYS_DEBUG("%s: static_endpoints bus_num (%d)...\n",
			       __func__, bus_num);
			int ret = 0;

			if (!daemon_mode) {
				ret = i2c_smbus_arp_init(out_fd);
				if (ret != 0)
					goto RELEASE_RESOURCE;
			}

			int retry = 3;

			while (retry-- > 0) {
				/* Reason for false positive - Checked the length for Out-of-bounds write */
				/* coverity[overrun-buffer-val : FALSE] */
				ret = send_direct_get_udid_command(
					out_fd, 0, inbuf, inbuf_len,
					GENERAL_COMMAND);
				MCTP_SYS_DEBUG("send_get_udid_command...ret: %d, slave_addr: %2x\n",
				       ret, inbuf[17]);

				if (inbuf[17] != 0xFF && ret == 0)
					break;
			}
			if (ret != 0)
				goto SCAN_RESOURCE;

			// Get slave address from UDID
			slave_address = inbuf[17] >> 1;
			MCTP_SYS_DEBUG("current slave_address 0x%x...\n",
			       slave_address);

			uint8_t interface_ASF = 0;
			// Check ASF bit from UDID
			interface_ASF = inbuf[8];
			interface_ASF = (interface_ASF >> 5) & 0x01;

			if (interface_ASF != 0x01) {
				MCTP_SYS_DEBUG("%s: ASF bit is not set, proceeding with MCTP version "
				       "check anyway.",
				       __func__);
				goto FIX_ADDRESS;
			}

			unsigned char Address_Type =
				GET_ADDR_TYPE(inbuf[BYTE1_CAPABILITIES]);
			if (slave_address == 0xFF || slave_address == 0x7F ||
			    Address_Type != ARP_FIXED_ADDR) {
				uint8_t free_address = find_free_slave_address(
					out_fd, slave_address);
				MCTP_SYS_INFO(
					"%s: find_free_slave_address %x...\n",
					__func__, free_address);
				if (slave_address == free_address) {
					goto FIX_ADDRESS;
				}
				slave_address = free_address;
			}

		FIX_ADDRESS:
			retry = 3;
			inbuf[17] = slave_address << 1;
			while (retry-- > 0) {
				ret = smbus_write_block_data(out_fd,
							     SET_ADDR_COMMAND,
							     17, &inbuf[1]);
				MCTP_SYS_DEBUG("i2c_smbus_set_address...0x%x, ret: %d\n",
				       slave_address, ret);
				if (ret == 0) {
					break;
				}
			}
			if (ret != 0)
				goto RELEASE_RESOURCE;

			retry = 3;
			while (retry-- > 0) {
				/* Reason for false positive - Checked the length for Out-of-bounds write */
				/* coverity[overrun-buffer-val : FALSE] */
				ret = send_direct_get_udid_command(
					out_fd, 0, inbuf, inbuf_len,
					slave_address << 1 | DIRECTED_COMMAND);
				MCTP_SYS_DEBUG("send_direct_get_udid_command...0x%x, ret: %d\n",
				       inbuf[17], ret);
				if (inbuf[17] != 0xFF && ret == 0)
					break;
			}

			if (ret != 0 || (inbuf[17] >> 1) != slave_address) {
				goto RELEASE_RESOURCE;
			}

			*target_address = slave_address;
			set_address_pool(slave_address);
			goto RELEASE_RESOURCE;
		}

	SCAN_RESOURCE:
		*target_address = i2c_bus_scan_address(out_fd, *target_address);
		if (*target_address != 0) {
			set_address_pool(*target_address);
		}

	RELEASE_RESOURCE:
		close(out_fd);
		i2c_mutex_unlock();
	}

	return EXIT_SUCCESS;
}

int i2c_smbus_find_location(int bus_num, char *parent_path, char *parent_name,
			    char *location)
{
	int32_t retval = EXIT_FAILURE;
	DIR *dir;
	struct dirent *ptr;
	char *endptr;
	char child_path[1024];
	char link_target[1024];

	if ((dir = opendir(parent_path)) == NULL) {
		MCTP_SYS_ERR("opendir(%s) failed!", parent_path);
		return EXIT_FAILURE;
	}

	while ((ptr = readdir(dir)) != NULL) {
		snprintf(child_path, sizeof(child_path), "%s/%s", parent_path,
			 ptr->d_name);
		struct stat info;
		int ret = lstat(child_path, &info);
		if (ret != 0)
			continue;

		if (S_ISLNK(info.st_mode)) {
			ssize_t len = readlink(child_path, link_target,
					       sizeof(link_target) - 1);
			if (len != -1) {
				link_target[len] = '\0';
				if (strncmp(link_target, "/dev/i2c-", 9) == 0) {
					uint8_t num = (uint8_t)strtoul(
						link_target + 9, &endptr, 10);
					if (num == bus_num) {
						char *pos = strstr(parent_name,
								   "_Mux");
						if (pos != NULL) {
							size_t length =
								pos -
								parent_name;
							strncpy(child_path,
								parent_name,
								length);
							child_path[length] =
								'\0'; // Null-terminate the result string
						} else {
							strcpy(child_path,
							       parent_name); // If "_Mux" not found, copy the whole string
						}
						if (location == NULL) {
							closedir(dir);
							return EXIT_SUCCESS;
						}

						snprintf(location, 256, "%s %s",
							 child_path,
							 ptr->d_name);

						char *str = location;
						while (*str != '\0') {
							if (*str == '_') {
								*str = ' ';
							}
							str++;
						}
						retval = EXIT_SUCCESS;
						break;
					}
				}
			}
		}
		if (S_ISDIR(info.st_mode)) {
			if (strcmp(ptr->d_name, ".") != 0 &&
			    strcmp(ptr->d_name, "..") != 0) {
				retval = i2c_smbus_find_location(bus_num,
								 child_path,
								 ptr->d_name,
								 location);
				if (retval == 0)
					break;
			}
		}
	}

	closedir(dir);
	return retval;
}
