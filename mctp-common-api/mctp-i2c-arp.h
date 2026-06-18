#ifndef __MCTP_I2C_ARP_H__
#define __MCTP_I2C_ARP_H__

#ifdef __cplusplus
extern "C" {
#endif

int set_pool_of_endpoints(int32_t bus_num, uint8_t *target_address,
			  bool daemon_mode);
int i2c_smbus_scan_address(int out_fd, u_int8_t address);
void clear_address_pool(unsigned char Addr);
int send_direct_get_udid_command(int out_fd, size_t idx, uint8_t *inbuf,
				 uint8_t len, uint8_t command);
void initial_i2c_address_pool();
int i2c_smbus_scan(uint8_t bus_num,
		   struct mctp_static_endpoint_mapper **static_endpoints_tab,
		   uint8_t *static_endpoints_len);
int i2c_smbus_find_location(int bus_num, char *parent_path, char *parent_name,
			    char *location);
uint8_t i2c_bus_scan_address(int32_t out_fd, uint8_t start_addr);
int i2c_bus_reset_device(int bus_num, u_int8_t slave_addr);
int i2c_smbus_detect_device(int file, uint8_t slave_addr);
void mctp_i2c_reset_discovery_state();

#ifdef __cplusplus
}
#endif
#endif
