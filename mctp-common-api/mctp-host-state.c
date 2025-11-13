#include <stdio.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include "mctp-utils.h"
#include "mctp-ctrl.h"
#include "mctp-discovery-common.h"
#include "mctp-sdbus.h"
#include "mctp-ext-sdbus.h"
#include "mctp-netlink.h"

int host_reset = 0;
int host_power = 0;
int host_power_changed = 0;

sd_bus_slot *host_reset_match_slot = NULL;
sd_bus_slot *host_power_match_slot = NULL;
sd_bus_slot *oem_match_slot = NULL;

int mctp_detect_power_state(sd_bus *bus)
{
	//sd_bus *bus = NULL;
	sd_bus_message *msg = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	const char *state = NULL;
	int ret;

	// Call the Get method on the Properties interface
	ret = sd_bus_call_method(
		bus,
		"xyz.openbmc_project.State.Host",   // service to contact
		"/xyz/openbmc_project/state/host0", // object path
		"org.freedesktop.DBus.Properties",  // interface name
		"Get",				    // method name
		&error,				    // object to return error in
		&msg,				    // return message on success
		"ss",				    // input signature
		"xyz.openbmc_project.State.Host",   // first argument
		"CurrentHostState");		    // second argument
	if (ret < 0) {
		MCTP_SYS_ERR("Failed to issue method call: %s\n",
			      error.message);
		goto finish;
	}

	// Read the response
	ret = sd_bus_message_read(msg, "v", "s", &state);
	if (ret < 0) {
		MCTP_SYS_ERR("Failed to parse response message: %s\n",
			      strerror(-ret));
		goto finish;
	}

	printf("CurrentHostState: %s\n", state);

finish:
	sd_bus_error_free(&error);
	sd_bus_message_unref(msg);

	return ret < 0 ? EXIT_FAILURE : strstr(state, ".Running") ? EXIT_SUCCESS : EXIT_FAILURE;
}

int mctp_detect_host_reset(sd_bus *bus)
{
	sd_bus_message *msg = NULL;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	int resetState;
	int ret;

	// Call the Get method on the Properties interface
	ret = sd_bus_call_method(
		bus,
		"xyz.openbmc_project.Host.Misc.Manager", // service to contact
		"/xyz/openbmc_project/misc/platform_state", // object path
		"org.freedesktop.DBus.Properties",	    // interface name
		"Get",					    // method name
		&error, // object to return error in
		&msg,	// return message on success
		"ss",	// input signature
		"xyz.openbmc_project.State.Host.Misc", // first argument
		"ESpiPlatformReset");		       // second argument
	if (ret < 0) {
		MCTP_SYS_ERR("Failed to issue method call: %s\n",
			      error.message);
		goto finish;
	}

	// Read the response
	ret = sd_bus_message_read(msg, "v", "b", &resetState);
	if (ret < 0) {
		MCTP_SYS_ERR("Failed to parse response message: %s\n",
			      strerror(-ret));
		goto finish;
	}

	MCTP_SYS_DEBUG("ESpiPlatformReset: %d\n", resetState);

finish:
	sd_bus_error_free(&error);
	sd_bus_message_unref(msg);

	return ret < 0 ? EXIT_FAILURE : !resetState ? EXIT_SUCCESS : EXIT_FAILURE;
}

int hostResetSignalHandler(sd_bus_message *m, void *userdata,
			   sd_bus_error *ret_error)
{
	(void)m;
	(void)userdata;
	(void)ret_error;
	const char *interface = NULL;
	int r;

	// Read interface name
	r = sd_bus_message_read(m, "s", &interface);
	if (r < 0)
		return r;

	if (strcmp(interface, "xyz.openbmc_project.State.Host.Misc") != 0)
		return 0; // Ignore other interfaces

	// Enter the a{sv} dictionary
	r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
	if (r < 0)
		return r;

	while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY,
						   "sv")) > 0) {
		const char *prop;
		r = sd_bus_message_read(m, "s", &prop);
		if (r < 0)
			return r;

		if (strcmp(prop, "ESpiPlatformReset") == 0) {
			const char *state;

			r = sd_bus_message_enter_container(
				m, SD_BUS_TYPE_VARIANT, "s");
			if (r < 0)
				return r;

			r = sd_bus_message_read(m, "s", &state);
			if (r < 0)
				return r;

			MCTP_SYS_DEBUG("ESpiPlatformReset changed to: %s\n",
					state);

			if (strcmp(state, "true") == 0)
				host_reset = 1;
			else
				host_reset = 0;

			r = sd_bus_message_exit_container(m); // variant
			if (r < 0)
				return r;
		} else {
			// Skip this variant
			r = sd_bus_message_skip(m, "v");
			if (r < 0)
				return r;
		}

		r = sd_bus_message_exit_container(m); // dict entry
		if (r < 0)
			return r;
	}

	r = sd_bus_message_exit_container(m); // a{sv}

	return r;
}

int powerSignalHandler(sd_bus_message *m, void *userdata,
		       sd_bus_error *ret_error)
{
	(void)m;
	(void)userdata;
	(void)ret_error;
	const char *interface = NULL;

	int r;
	// Read interface name
	r = sd_bus_message_read(m, "s", &interface);
	if (r < 0)
		return r;

	if (strcmp(interface, "xyz.openbmc_project.State.Host") != 0)
		return 0; // Ignore other interfaces

	// Enter the a{sv} dictionary
	r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
	if (r < 0)
		return r;

	while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY,
						   "sv")) > 0) {
		const char *prop;
		r = sd_bus_message_read(m, "s", &prop);
		if (r < 0)
			return r;

		if (strcmp(prop, "CurrentHostState") == 0) {
			const char *state;

			r = sd_bus_message_enter_container(
				m, SD_BUS_TYPE_VARIANT, "s");
			if (r < 0)
				return r;

			r = sd_bus_message_read(m, "s", &state);
			if (r < 0)
				return r;

			MCTP_SYS_DEBUG("CurrentHostState changed to: %s\n",
					state);

			int current_host_power = strstr(state, ".Running") ? 0 : 1;
			host_power_changed = current_host_power != host_power ? 1: 0;
			host_power = current_host_power;
			
			r = sd_bus_message_exit_container(m); // variant
			if (r < 0)
				return r;
		} else {
			// Skip this variant
			r = sd_bus_message_skip(m, "v");
			if (r < 0)
				return r;
		}

		r = sd_bus_message_exit_container(m); // dict entry
		if (r < 0)
			return r;
	}

	r = sd_bus_message_exit_container(m); // a{sv}
	return r;
}

int oemSignalHandler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	(void)m;
	(void)userdata;
	(void)ret_error;
	const char *interface = NULL;
	int r;

	// Read interface name
	r = sd_bus_message_read(m, "s", &interface);
	if (r < 0)
		return r;

	if (strcmp(interface, "xyz.openbmc_project.State.ServiceReady") != 0)
		return 0; // Ignore other interfaces

	// Enter the a{sv} dictionary
	r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
	if (r < 0)
		return r;

	while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY,
						   "sv")) > 0) {
		const char *prop;
		r = sd_bus_message_read(m, "s", &prop);
		if (r < 0)
			return r;

		if (strcmp(prop, "OemExtensionPath") == 0) {
			const char *state;

			r = sd_bus_message_enter_container(
				m, SD_BUS_TYPE_VARIANT, "s");
			if (r < 0)
				return r;

			r = sd_bus_message_read(m, "s", &state);
			if (r < 0)
				return r;

			MCTP_SYS_DEBUG("OemExtensionPath changed to: %s\n",
					state);

			r = sd_bus_message_exit_container(m); // variant
			if (r < 0)
				return r;
		} else {
			// Skip this variant
			r = sd_bus_message_skip(m, "v");
			if (r < 0)
				return r;
		}

		r = sd_bus_message_exit_container(m); // dict entry
		if (r < 0)
			return r;
	}

	r = sd_bus_message_exit_container(m); // a{sv}
	return r;
}

int registerHostMatch(sd_bus *bus)
{
	int ret = sd_bus_add_match(
		bus, &host_reset_match_slot,
		"type='signal',"
		"interface='org.freedesktop.DBus.Properties',"
		"member='PropertiesChanged',"
		//        "member='ESpiPlatformReset',"
		"path='/xyz/openbmc_project/misc/platform_state'",
		//        "arg0='xyz.openbmc_project.State.Host.Misc',",
		hostResetSignalHandler, NULL);
	MCTP_SYS_DEBUG("registerHostMatch: %d\n", ret);
	return ret;
}

int registerPowerMatch(sd_bus *bus)
{
	int ret = sd_bus_add_match(
		bus, &host_power_match_slot,
		"type='signal',"
		"interface='org.freedesktop.DBus.Properties',"
		"member='PropertiesChanged',"
		//        "member='CurrentHostState',"
		"path='/xyz/openbmc_project/state/host0',",
		//        "arg0='xyz.openbmc_project.State.Host'",
		powerSignalHandler, NULL);
	MCTP_SYS_DEBUG("registerPowerMatch: %d\n", ret);
	return ret;
}

int registerOemMatch(sd_bus *bus)
{
	int ret = sd_bus_add_match(
		bus, &oem_match_slot,
		"type='signal',"
		"interface='org.freedesktop.DBus.Properties',"
		"member='PropertiesChanged',"
		//        "member='OemExtensionPath',"
		"path='/xyz/openbmc_project/mctp/PCIe',",
		//        "arg0='xyz.openbmc_project.State.ServiceReady'",
		oemSignalHandler, NULL);
	MCTP_SYS_DEBUG("registerOemMatch: %d\n", ret);
	return ret;
}

int mctp_register_host_state_signal(sd_bus *bus)
{
	host_power = mctp_detect_power_state(bus);
	//host_reset = mctp_detect_host_reset();
	//registerOemMatch(bus);
	//registerHostMatch(bus);
	registerPowerMatch(bus);
	return 0;
}

int mctp_deregister_host_state_signal() {
	if (host_power_match_slot) {
		sd_bus_slot_unref(host_power_match_slot);
		host_power_match_slot = NULL;
	}
#if 0
	if (oem_match_slot) {
		sd_bus_slot_unref(oem_match_slot);
		oem_match_slot = NULL;
	}
	if (host_reset_match_slot) {
		sd_bus_slot_unref(host_reset_match_slot);
		host_reset_match_slot = NULL;
	}
#endif
	return 0;
}

int mctp_ctrl_handle_host_reset(mctp_ctrl_t *mctp_ctrl)
{
	MCTP_SYS_INFO("%s: Host reset detected. Clear all endpoints.\n", __func__);
	mctp_ctrl_sdbus_object_remove_all_signal(mctp_ctrl->bus);	
	mctp_routing_entry_delete_all();
	mctp_uuid_delete_all();
	mctp_vdm_delete_all();
	mctp_msg_types_delete_all();
	
	/* Reset the host_power_changed flag after handling the reset */
	host_power_changed = 0;
	
	return 0;
}

int mctp_check_host_reset_event()
{
	return host_power_changed;
}
