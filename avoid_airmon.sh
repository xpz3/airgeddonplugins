#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="Avoid airmon"
plugin_description="Plugin to avoid use of airmon"
plugin_author="xpz3"

plugin_enabled=1

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""

plugin_distros_supported=("*")

#Override check_airmon_compatibility function in order to force to avoid airmon use
function avoid_airmon_override_check_airmon_compatibility() {

	debug_print

	if [ "${1}" = "interface" ]; then
		set_chipset "${interface}" "read_only"

		interface_airmon_compatible=0
	else
		set_chipset "${secondary_wifi_interface}" "read_only"

		secondary_interface_airmon_compatible=0
	fi
}
