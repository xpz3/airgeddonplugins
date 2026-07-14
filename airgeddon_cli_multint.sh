#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154,SC2124,SC2010,SC2027

# ============================================================================
# airgeddon_cli_multint.sh
#
# Combined plugin: CLI non-interactive automation + dual Wi-Fi adapter support
# for Evil Twin with Captive Portal attack.
#
# Merges:
#   airgeddon_cli.sh
#   multint.sh
#
# New switches added on top of every original airgeddon_cli switch:
#   --ap-interface <interface>     : interface for fake AP (master mode)
#   --deauth-interface <interface> : interface for deauth/monitor (monitor mode)
#
# When BOTH --ap-interface and --deauth-interface are supplied, VIF is not
# required and two separate cards handle each role independently.
# When only -i/--interface is supplied, original single-VIF mode is used.
#
# Author  : xpz3
# License : GPL-3.0
# Minimum airgeddon : 12.02
# ============================================================================

plugin_name="airgeddon_cli_multint"
plugin_description="CLI + dual-adapter support for Evil Twin Captive Portal attack"
plugin_author="xpz3"

plugin_enabled=1

plugin_minimum_ag_affected_version="12.02"
plugin_maximum_ag_affected_version=""

plugin_distros_supported=("*")

AIRGEDDON_DEVELOPMENT_MODE="true" # Do not change this value

# ── State variables (from airgeddon_cli) ─────────────────────────────────────
airgeddon_cli_targets_default_path=""  # Set from function below if left empty
airgeddon_cli_tmux_active=0
airgeddon_cli_active=1
airgeddon_cli_skip=1

# ── Default attack values (from airgeddon_cli) ────────────────────────────────
airgeddon_cli_arguments_copy="$@"
airgeddon_cli_filemode=0
et_dos_attack="Aireplay"
advanced_captive_portal=0
captive_portal_language="ENGLISH"
dos_pursuit_mode=0
selected_network_type_text="personal"
unselected_network_type_text="enterprise"
airgeddon_cli_multint_secondary_wifi_interface=""

# ── Dual-interface state variables (from multint) ─────────────────────────────
multint_enabled=0
multint_ap_interface=""
multint_deauth_interface=""

# ============================================================================
# USAGE / HELP
# ============================================================================

function airgeddon_cli_multint_print_usage() {

	debug_print

	echo
	echo $'bash' "${scriptname}" $'[-a|-advportal|--advportal]\n\t[-b|-bssid|--bssid <bssid>]\n\t[-c|-channel|--channel <channel>]\n\t[-cl|--cl <captive portal password log path>]\n\t[-d|-debug|--debug]\n\t[-dos|--dos <DoS mode>]\n\t[-e|-essid|--essid <essid>]\n\t[-enc|--enc <encryption type>]\n\t[-f|-file|--file <filename>]\n\t[-h|-hsfile|--hsfile <handshakefilepath>]\n\t[-i|-interface|--interface <interface>]\n\t[--ap-interface <ap_interface>]\n\t[--deauth-interface <deauth_interface>]\n\t[-l|-cplang|--cplang <captive portal language>]\n\t[-m|-ms|--ms]\n\t[-nk|--nk]\n\t[-p|-dp|--dp <DoS pursuit interface>]\n\t[-t|-tmux|--tmux]\n\t[-u|-usage|--usage]\n\t[-v|-version|--version]'
	echo
	echo $'\t[-a|-advportal|--advportal]\n\t\tEnable advanced captive portal'
	echo $'\t[-b|-bssid|--bssid <bssid>]\n\t\tSpecify target bssid'
	echo $'\t[-c|-channel|--channel <channel>]\n\t\tSpecify target channel'
	echo $'\t[-cl|--cl <captive portal password log path>]\n\t\tSpecify captive portal password save path on successful capture'
	echo $'\t[-d|-debug|--debug]\n\t\tSet AIRGEDDON_DEBUG_MODE=true'
	echo $'\t[-dos|--dos <DoS mode>]\n\t\tSpecify DoS attack option: 1=mdk4|mdk3 2=Aireplay-ng 3=Auth DoS'
	echo $'\t[-e|-essid|--essid <essid>]\n\t\tSpecify target essid'
	echo $'\t[-enc|--enc <encryption type>]\n\t\tSpecify target AP encryption {WPA|WPA2}'
	echo $'\t[-f|-file|--file <filename>]\n\t\tSpecify the filename containing target AP essid, bssid, channel, encryption\n\t\tand handshake file path delimited by "|" character.\n\t\tIf this option is used, the values from the file will override any other\n\t\tvalues specified by command line.'
	echo $'\t[-h|-hsfile|--hsfile <handshakefilepath>]\n\t\tSpecify the location of target AP handshake file'
	echo $'\t[-i|-interface|--interface <interface>]\n\t\tSpecify a single VIF-capable interface for captive portal attack.\n\t\tThe interface MUST be in Managed mode before starting airgeddon.\n\t\tCannot be used together with --ap-interface / --deauth-interface.'
	echo $'\t[--ap-interface <ap_interface>]\n\t\tSpecify the interface used for the fake AP (master mode).\n\t\tMust be used together with --deauth-interface.\n\t\tThe interface MUST be in Managed mode before starting airgeddon.\n\t\tWhen this pair is used, VIF support is not required.'
	echo $'\t[--deauth-interface <deauth_interface>]\n\t\tSpecify the interface used for deauth packets (monitor mode).\n\t\tMust be used together with --ap-interface.'
	echo $'\t[-l|-cplang|--cplang <captive portal language>]\n\t\tSpecify the language to be used on captive portal. Default is ENGLISH'
	echo $'\t[-m|-ms|--ms]\n\t\tEnable mac address spoofing'
	echo $'\t[-nk|--nk]\n\t\tSet AIRGEDDON_FORCE_NETWORK_MANAGER_KILLING=false'
	echo $'\t[-p|-dp|--dp <DoS pursuit interface>]\n\t\tEnable DoS pursuit mode. Specify the second interface name'
	echo $'\t[-t|-tmux|--tmux]\n\t\tSet AIRGEDDON_WINDOWS_HANDLING=tmux and start airgeddon inside tmux'
	echo $'\t[-v|-version|--version]\n\t\tPrints airgeddon version'
	echo $'\t[-u|-usage|--usage]\n\t\tPrints usage'
	echo
	echo $'\tEXAMPLES:'
	echo
	echo $'\t  Dual-adapter + file:\n\t  bash airgeddon.sh --ap-interface wlan0 --deauth-interface wlan1 --file targets.txt'
	echo
	echo $'\t  Dual-adapter + full args:\n\t  bash airgeddon.sh --ap-interface wlan0 --deauth-interface wlan1 \\\n\t    --bssid AA:BB:CC:DD:EE:FF --essid "HomeNetwork" --channel 6 \\\n\t    --enc WPA2 --hsfile /root/captures/HomeNetwork.cap'
	echo
	echo $'\t  Single VIF-capable adapter + file (original cli mode):\n\t  bash airgeddon.sh --interface wlan0 --file targets.txt'
	echo
	echo $'\t  Single VIF-capable adapter + full args (original cli mode):\n\t  bash airgeddon.sh -i wlan0 -b AA:BB:CC:DD:EE:FF -e "HomeNetwork" \\\n\t    -c 6 --enc WPA2 -h /root/captures/HomeNetwork.cap'
}

# ============================================================================
# CUSTOM FUNCTIONS
# ============================================================================

#shellcheck disable=SC2164
function airgeddon_cli_multint_get_absolute_script_path() {

	debug_print

	if [ "${0}" != "${scriptname}" ]; then
		airgeddon_cli_relative_path=$(pwd)
		cd "${airgeddon_cli_relative_path}"
		cd "${0%/*}"
		airgeddon_cli_absolute_script_path=$(pwd)
	else
		airgeddon_cli_absolute_script_path=$(pwd)
	fi
}

function airgeddon_cli_multint_manage_captive_portal_log() {

	debug_print

	default_et_captive_portal_logpath="${default_save_path}"
	default_et_captive_portallogfilename=$(sanitize_path "evil_twin_captive_portal_password-${essid}.txt")
	default_et_captive_portal_logpath="${default_et_captive_portal_logpath}${default_et_captive_portallogfilename}"
	validpath=1
}

# Read pipe-separated target values from file.
# File format (produced by mass_handshake_capture.sh): essid|bssid|channel|encryption|/path/to/handshake.cap
function airgeddon_cli_multint_read_target_values() {

	debug_print

	local airgeddon_cli_values_from_file=""
	read -r airgeddon_cli_values_from_file < "${airgeddon_cli_targets_default_path}${airgeddon_cli_target_file}"

	essid=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0,v,"|"); print v[1]}')
	bssid=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0,v,"|"); print v[2]}')
	channel=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0,v,"|"); print v[3]}')
	enc=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0,v,"|"); print v[4]}')
	et_handshake=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0,v,"|"); print v[5]}')
}

# Validate all parsed parameters before launching the attack
# Extended from the original to handle dual-interface mode
function airgeddon_cli_multint_verify_parameters() {

	debug_print

	if [[ "${airgeddon_cli_tmux_active}" -eq 1 ]]; then
		return
	fi

	# Validate target network values
	if ! [[ "${bssid}" =~ ^([[:xdigit:]]{2}[:]){5}([[:xdigit:]]{2})$ ]]; then
		language_strings "${language}" "climult_err_invalid_bssid" "red"
		exit
	fi
	if [[ -z "${essid}" ]] || [[ -z "${channel}" ]] || [[ -z "${enc}" ]]; then
		language_strings "${language}" "climult_err_invalid_target_vals" "red"
		exit
	fi
	if [[ "${et_handshake}" = "" ]]; then
		language_strings "${language}" "climult_err_no_handshake" "red"
		exit
	fi

	# ── DUAL-ADAPTER MODE validation ─────────────────────────────────────────
	if [[ "${multint_enabled}" -eq 1 ]]; then

		# Validate AP interface
		if [[ -z "${multint_ap_interface}" ]]; then
			language_strings "${language}" "climult_err_no_ap_iface" "red"
			exit
		fi
		local airgeddon_cli_multint_mode
		airgeddon_cli_multint_mode=$(iw "${multint_ap_interface}" info 2>/dev/null | grep type | awk '{print $2}')
		if [[ "${airgeddon_cli_multint_mode^}" != "Managed" ]]; then
			language_strings "${language}" "climult_err_ap_managed" "red"
			exit
		fi

		# Validate deauth interface
		if [[ -z "${multint_deauth_interface}" ]]; then
			language_strings "${language}" "climult_err_no_deauth_iface" "red"
			exit
		fi
		airgeddon_cli_multint_mode=$(iw "${multint_deauth_interface}" info 2>/dev/null | grep type | awk '{print $2}')
		if [[ "${airgeddon_cli_multint_mode^}" != "Managed" ]]; then
			language_strings "${language}" "climult_err_deauth_managed" "red"
			exit
		fi
		if [[ "${multint_ap_interface}" = "${multint_deauth_interface}" ]]; then
			language_strings "${language}" "climult_err_ap_deauth_same" "red"
			exit
		fi

		interface="${multint_ap_interface}"
		phy_interface=$(physical_interface_finder "${interface}")
		interface_mac=$(ip link show "${interface}" | awk '/ether/ {print $2}')

		if [[ -n "${phy_interface}" ]]; then
			check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
			check_supported_standards "${phy_interface}"
			# Suppress VIF check — two separate cards are in use
			adapter_vif_support=1
			check_interface_wifi_longname "${interface}"
		else
			adapter_vif_support=0
			standard_80211n=0
			standard_80211ac=0
			standard_80211ax=0
			standard_80211be=0
		fi
		current_iface_on_messages="${interface}"

	# ── SINGLE VIF-CAPABLE ADAPTER MODE validation ────────────────────────────
	else
		if [[ -z "${interface}" ]]; then
			language_strings "${language}" "climult_err_no_iface" "red"
			exit
		fi
		local airgeddon_cli_interface_mode=$(iw "${interface}" info 2> /dev/null | grep type | awk '{print $2}')
		if [[ "${airgeddon_cli_interface_mode^}" != "Managed" ]];then
			language_strings "${language}" "climult_err_iface_managed" "red"
			exit
		fi
	fi
}

# Main CLI parameter processing. Called from the main_menu prehook.
function airgeddon_cli_multint_parse_parameters() {

	debug_print

	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
		transfer_to_tmux "${airgeddon_cli_arguments_copy}"
		if ! check_inside_tmux; then
			exit_code=1
			exit ${exit_code}
		fi
	fi

	airgeddon_cli_multint_get_absolute_script_path
	airgeddon_cli_multint_verify_parameters
	airgeddon_cli_multint_manage_captive_portal_log
	et_captive_portal_logpath="${default_et_captive_portal_logpath}"

	et_mode="et_captive_portal"
	ifacemode="Managed"
	ifacemode_deauth="Monitor"

	if ! check_target_band_supported_by_interface "main_wifi_interface"; then
		exit_code=1
		exit ${exit_code}
	fi

	language_strings "${language}" 101 "title"
	print_iface_selected
	print_all_target_vars
	echo
	language_strings "${language}" 296 "yellow"

	exec_et_captive_portal_attack
	evil_twin_attacks_menu
	airgeddon_cli_active=0
	airgeddon_cli_skip=1
	main_menu
}

# ============================================================================
# Triggers CLI parameter processing just before the main menu renders.
# ============================================================================
function airgeddon_cli_multint_prehook_main_menu() {

	debug_print

	if [ "${airgeddon_cli_skip}" = 0 ]; then
		if [ "${airgeddon_cli_active}" -eq 1 ]; then
			airgeddon_cli_multint_parse_parameters
		fi
	fi
}

# ============================================================================
# Set some variables and do checks needed for evil twin attack.
# ============================================================================
function airgeddon_cli_multint_et_prerequisites() {

	debug_print

	if hash arping-th 2> /dev/null; then
		right_arping=1
		right_arping_command="arping-th"
	elif hash arping 2> /dev/null; then
		if check_right_arping; then
			right_arping=1
		else
			echo
			language_strings "${language}" 722 "yellow"
			language_strings "${language}" 115 "read"
		fi
	fi

	rm -rf "${tmpdir}${channelfile}" > /dev/null 2>&1
	echo "${channel}" > "${tmpdir}${channelfile}"
	rm -rf "${tmpdir}${bandfile}" > /dev/null 2>&1
	echo "${target_band_id}" > "${tmpdir}${bandfile}"
}

# ============================================================================
# Runs the Evil Twin Captive Portal attack directly without interactive prompts.
# ============================================================================
function airgeddon_cli_multint_override_exec_et_captive_portal_attack() {

	debug_print

	rm -rf "${tmpdir}${webdir}" > /dev/null 2>&1
	mkdir "${tmpdir}${webdir}" > /dev/null 2>&1

	airgeddon_cli_multint_et_prerequisites
	prepare_et_interface
	set_hostapd_config
	launch_fake_ap
	set_network_interface_data
	set_dhcp_config
	set_std_internet_routing_rules
	launch_dhcp_server
	exec_et_deauth
	set_et_control_script
	launch_et_control_window
	launch_dns_blackhole
	prepare_captive_portal_data
	set_webserver_config
	set_captive_portal_page
	launch_webserver
	write_et_processes

	echo
	language_strings "${language}" 298 "yellow"
	language_strings "${language}" 115 "read"

	kill_et_windows

	if [ "${dos_pursuit_mode}" -eq 1 ]; then
		recover_current_channel
	fi

	restore_et_interface
	clean_tmpfiles
}

# ============================================================================
# In CLI mode (airgeddon_cli_skip=0): skips the interactive selection entirely
# because interface(s) are already set from the getopt parsing block below.
# In interactive mode (no CLI args): shows the dual-adapter selection UI
# from multint so the user picks two separate cards.
# ============================================================================
function airgeddon_cli_multint_override_select_interface() {

	debug_print

	# CLI MODE: interfaces already set during arg parsing
	if [[ "${airgeddon_cli_active}" == 1 ]] && [[ "${airgeddon_cli_skip}" == 0 ]]; then
		return
	fi

	# INTERACTIVE DUAL-ADAPTER MODE (no CLI args, from multint)
	local interface_menu_band
	local multintcounter=0
	multint_enabled=1

	while [[ "${multintcounter}" -lt 2 ]]; do
		clear
		language_strings "${language}" 88 "title"
		current_menu="select_interface_menu"

		if [[ "${multintcounter}" -eq 0 ]]; then
			language_strings "${language}" "climult_sel_ap" "green"
		else
			language_strings "${language}" "climult_sel_deauth" "green"
		fi

		print_simple_separator
		ifaces=$(ip link | grep -E "^[0-9]+" | cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v)
		option_counter=0
		for item in ${ifaces}; do
			option_counter=$((option_counter + 1))
			if [[ ${#option_counter} -eq 1 ]]; then spaceiface="  "
			else spaceiface=" "; fi
			echo -ne "${option_counter}.${spaceiface}${item} "
			set_chipset "${item}"
			if [[ "${chipset}" = "" ]]; then
				language_strings "${language}" 245 "blue"
			else
				interface_menu_band=""
				if check_interface_wifi "${item}"; then
					interface_menu_band+="${blue_color}// ${pink_color}"
					get_5ghz_band_info_from_phy_interface "$(physical_interface_finder "${item}")"
					case "$?" in
						"1") interface_menu_band+="${band_24ghz}" ;;
						*)   interface_menu_band+="${band_24ghz}, ${band_5ghz}" ;;
					esac
				fi
				if [[ "${is_rtl_language}" -eq 1 ]]; then
					echo -e "${interface_menu_band} ${blue_color}// ${normal_color}${chipset} ${yellow_color}:Chipset${normal_color}"
				else
					echo -e "${interface_menu_band} ${blue_color}// ${yellow_color}Chipset:${normal_color} ${chipset}"
				fi
			fi
		done
		print_hint

		read -rp "> " iface
		if [[ ! ${iface} =~ ^[[:digit:]]+$ ]] || ((iface < 1 || iface > option_counter)); then
			invalid_iface_selected
		else
			option_counter2=0
			for item2 in ${ifaces}; do
				option_counter2=$((option_counter2 + 1))
				if [[ "${iface}" = "${option_counter2}" ]]; then
					if [[ "${multintcounter}" -eq 0 ]]; then
						multint_ap_interface="${item2}"
						current_iface_on_messages="${multint_ap_interface}"
						if ! set_mode_without_airmon "${multint_ap_interface}" "managed"; then
							echo
							language_strings "${language}" 1 "red"
							language_strings "${language}" 115 "read"
							multintcounter=$((multintcounter - 1))
						fi
					else
						multint_deauth_interface="${item2}"
						current_iface_on_messages="${multint_deauth_interface}"
						interface="${item2}"
						if [[ "${multint_ap_interface}" = "${multint_deauth_interface}" ]]; then
							echo
							language_strings "${language}" "climult_err_same_int" "red"
							language_strings "${language}" 115 "read"
							multintcounter=$((multintcounter - 1))
							break
						fi
						phy_interface=$(physical_interface_finder "${interface}")
						interface_mac=$(ip link show "${interface}" | awk '/ether/ {print $2}')
						if [[ -n "${phy_interface}" ]]; then
							check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
							check_supported_standards "${phy_interface}"
							adapter_vif_support=1
							check_interface_wifi_longname "${interface}"
						else
							adapter_vif_support=0
							standard_80211n=0
							standard_80211ac=0
							standard_80211ax=0
							standard_80211be=0
						fi
						current_iface_on_messages="${interface}"
						break
					fi
				fi
			done
		fi
		multintcounter=$((multintcounter + 1))
	done

	if [[ "${multint_ap_interface}" = "${multint_deauth_interface}" ]]; then
		multint_enabled=0
	fi
}

function airgeddon_cli_multint_override_check_airmon_compatibility() {

	debug_print

	interface_airmon_compatible=0
	secondary_interface_airmon_compatible=0
}

# ============================================================================
# Use the dedicated deauth card directly as the monitor interface.
# When not in dual mode, falls back to original VIF behaviour.
# ============================================================================
function airgeddon_cli_multint_override_prepare_et_monitor() {

	debug_print
	disable_rfkill

	if [[ "${multint_enabled}" -eq 1 ]]; then
		iface_monitor_et_deauth="${multint_deauth_interface}"
		ip link set "${iface_monitor_et_deauth}" down > /dev/null 2>&1
		iw "${iface_monitor_et_deauth}" set type monitor 2>/dev/null
	else
		iface_phy_number=${phy_interface:3:1}
		iface_monitor_et_deauth="mon${iface_phy_number}"
		iw phy "${phy_interface}" interface add "${iface_monitor_et_deauth}" \
		   type monitor 2>/dev/null
	fi

	ip link set "${iface_monitor_et_deauth}" up > /dev/null 2>&1
	iw "${iface_monitor_et_deauth}" set channel "${channel}" > /dev/null 2>&1
}

# ============================================================================
# Swap `interface` to the AP card while the deauth card stays in monitor mode.
# ============================================================================
function airgeddon_cli_multint_override_prepare_et_interface() {

	debug_print
	et_initial_state=${ifacemode}

	if [[ "${airgeddon_cli_active}" == 0 ]] && [[ "${airgeddon_cli_skip}" == 1 ]]; then
		interface="${multint_ap_interface}"
	fi

	if [[ "${multint_enabled}" -eq 1 ]]; then
		ifacemode="Managed"
		current_iface_on_messages="${interface}"
	fi

	if [[ "${ifacemode}" != "Managed" ]]; then
		check_airmon_compatibility "interface"
		if [[ "${interface_airmon_compatible}" -eq 1 ]]; then
			new_interface=$(${airmon} stop "${interface}" 2>/dev/null | \
			                grep station | head -n 1)
			ifacemode="Managed"
			[[ ${new_interface} =~ \]?([A-Za-z0-9]+)\)?$ ]] && \
				new_interface="${BASH_REMATCH[1]}"
			if [[ "${interface}" != "${new_interface}" ]]; then
				if check_interface_coherence; then
					interface=${new_interface}
					phy_interface=$(physical_interface_finder "${interface}")
					check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
					current_iface_on_messages="${interface}"
				fi
				echo
				language_strings "${language}" 15 "yellow"
			fi
		else
			if ! set_mode_without_airmon "${interface}" "managed"; then
				echo
				language_strings "${language}" 1 "red"
				language_strings "${language}" 115 "read"
				return 1
			else
				ifacemode="Managed"
			fi
		fi
	fi
}

# ============================================================================
# Prehook to restore DoS Pursuit mode interface to initial state.
# ============================================================================
function airgeddon_cli_multint_prehook_hardcore_exit() {

	debug_print

	if [[ "${multint_enabled}" -eq 1 ]]; then
		set_mode_without_airmon "${multint_deauth_interface}" "managed"
		if [ "${dos_pursuit_mode}" -eq 1 ]; then
			set_mode_without_airmon "${airgeddon_cli_multint_secondary_wifi_interface}" "managed"
		fi
	fi
}

# ============================================================================
# Prehook to restore DoS Pursuit mode interface to initial state.
# ============================================================================
function airgeddon_cli_multint_prehook_exit_script_option() {

	debug_print

	if [[ "${multint_enabled}" -eq 1 ]]; then
		set_mode_without_airmon "${multint_deauth_interface}" "managed"
		if [ "${dos_pursuit_mode}" -eq 1 ]; then
			set_mode_without_airmon "${airgeddon_cli_multint_secondary_wifi_interface}" "managed"
		fi
	fi
}

# ============================================================================
# Restore all used interfaces to initial states after the attack ends.
# ============================================================================
function airgeddon_cli_multint_override_restore_et_interface() {

	debug_print

	if [[ "${multint_enabled}" -eq 1 ]]; then
		# Restore cards back to managed mode
		set_mode_without_airmon "${multint_ap_interface}" "managed"
		set_mode_without_airmon "${multint_deauth_interface}" "managed"
		if [ "${dos_pursuit_mode}" -eq 1 ]; then
			while pgrep -f "airodump-ng.*${airgeddon_cli_multint_secondary_wifi_interface}" >/dev/null; do
				sleep 0.1
			done
			set_mode_without_airmon "${airgeddon_cli_multint_secondary_wifi_interface}" "managed"
		fi
		ifacemode="Managed"
	fi

	echo
	language_strings "${language}" 299 "blue"
	disable_rfkill
	mac_spoofing_desired=0

	# Only delete the monitor interface when in single-VIF mode.
	# In dual mode iface_monitor_et_deauth is the physical deauth card —
	# deleting it with `iw dev del` would remove the physical interface.
	if [[ "${multint_enabled}" -eq 0 ]]; then
		iw dev "${iface_monitor_et_deauth}" del > /dev/null 2>&1
	fi

	ip addr del "${et_ip_router}/${std_c_mask}" dev "${interface}" > /dev/null 2>&1
	ip route del "${et_ip_range}/${std_c_mask_cidr}" dev "${interface}" \
	   table local proto static scope link > /dev/null 2>&1

	if [[ "${multint_enabled}" -eq 0 ]]; then
		if [[ "${et_initial_state}" = "Managed" ]]; then
			set_mode_without_airmon "${interface}" "managed"
			ifacemode="Managed"
		else
			if [[ "${interface_airmon_compatible}" -eq 1 ]]; then
				new_interface=$(${airmon} start "${interface}" 2>/dev/null | \
				                grep monitor)
				desired_interface_name=""
				[[ ${new_interface} =~ ^You[[:space:]]already[[:space:]]have[[:space:]]a[[:space:]]([A-Za-z0-9]+)[[:space:]]device ]] && \
					desired_interface_name="${BASH_REMATCH[1]}"
				if [[ -n "${desired_interface_name}" ]]; then
					echo
					language_strings "${language}" 435 "red"
					language_strings "${language}" 115 "read"
					return
				fi
				ifacemode="Monitor"
				[[ ${new_interface} =~ \]?([A-Za-z0-9]+)\)?$ ]] && \
					new_interface="${BASH_REMATCH[1]}"
				if [[ "${interface}" != "${new_interface}" ]]; then
					interface=${new_interface}
					phy_interface=$(physical_interface_finder "${interface}")
					check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
					current_iface_on_messages="${interface}"
				fi
			else
				if set_mode_without_airmon "${interface}" "monitor"; then
					ifacemode="Monitor"
				fi
			fi
		fi
	fi

	control_routing_status "end"
}

# ============================================================================
# Interactive mode to select secondary Wi-Fi interface for DoS Pursuit
# when CLI mode is not enabled and interactive multint mode is chosen
# Exclude the AP and Deauth adapter from secondary interfaces in dual mode.
# ============================================================================
function airgeddon_cli_multint_override_select_secondary_interface() {

	debug_print

	if [[ "${return_to_et_main_menu}" -eq 1 ]]; then return 1; fi
	if [[ "${return_to_enterprise_main_menu}" -eq 1 ]]; then return 1; fi

	clear
	if [[ -n "${enterprise_mode}" ]]; then
		current_menu="enterprise_attacks_menu"
		case ${enterprise_mode} in
			"smooth") language_strings "${language}" 522 "title" ;;
			"noisy")  language_strings "${language}" 523 "title" ;;
		esac
	elif [[ -z "${enterprise_mode}" ]] && [[ -z "${et_mode}" ]]; then
		current_menu="dos_attacks_menu"
	elif [[ -z "${enterprise_mode}" ]] && [[ -n "${et_mode}" ]]; then
		current_menu="evil_twin_attacks_menu"
		case ${et_mode} in
			"et_onlyap")                  language_strings "${language}" 270 "title" ;;
			"et_sniffing")                language_strings "${language}" 291 "title" ;;
			"et_sniffing_sslstrip2")      language_strings "${language}" 292 "title" ;;
			"et_sniffing_sslstrip2_beef") language_strings "${language}" 397 "title" ;;
			"et_captive_portal")          language_strings "${language}" 293 "title" ;;
		esac
	fi

	if [[ "${1}" = "dos_pursuit_mode" ]]; then
		if [[ "${multint_enabled}" -eq 1 ]]; then
			readarray -t secondary_ifaces < <(iw dev | grep "Interface" | \
				awk '{print $2}' | grep "${interface}" -v | \
				grep "${multint_ap_interface}" -v)
		else
			readarray -t secondary_ifaces < <(iw dev | grep "Interface" | \
				awk '{print $2}' | grep "${interface}" -v)
		fi
	elif [[ "${1}" = "internet" ]]; then
		if [[ "${multint_enabled}" -eq 1 ]]; then
			if [[ -n "${secondary_wifi_interface}" ]]; then
				readarray -t secondary_ifaces < <(ip link | grep -E "^[0-9]+" | \
					cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v | \
					grep "${interface}" -v | grep "${secondary_wifi_interface}" -v | \
					grep "${multint_ap_interface}" -v)
			else
				readarray -t secondary_ifaces < <(ip link | grep -E "^[0-9]+" | \
					cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v | \
					grep "${interface}" -v | grep "${multint_ap_interface}" -v)
			fi
		else
			if [[ -n "${secondary_wifi_interface}" ]]; then
				readarray -t secondary_ifaces < <(ip link | grep -E "^[0-9]+" | \
					cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v | \
					grep "${interface}" -v | grep "${secondary_wifi_interface}" -v)
			else
				readarray -t secondary_ifaces < <(ip link | grep -E "^[0-9]+" | \
					cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v | \
					grep "${interface}" -v)
			fi
		fi
	fi

	if [[ ${#secondary_ifaces[@]} -eq 1 ]]; then
		if [[ "${1}" = "dos_pursuit_mode" ]]; then
			secondary_wifi_interface="${secondary_ifaces[0]}"
			secondary_phy_interface=$(physical_interface_finder "${secondary_wifi_interface}")
			check_interface_supported_bands "${secondary_phy_interface}" "secondary_wifi_interface"
		elif [[ "${1}" = "internet" ]]; then
			internet_interface="${secondary_ifaces[0]}"
		fi
		echo
		language_strings "${language}" 662 "yellow"
		language_strings "${language}" 115 "read"
		return 0
	fi

	option_counter=0
	for item in "${secondary_ifaces[@]}"; do
		if [[ "${option_counter}" -eq 0 ]]; then
			if [[ "${1}" = "dos_pursuit_mode" ]]; then
				echo; language_strings "${language}" 511 "green"
			elif [[ "${1}" = "internet" ]]; then
				echo; language_strings "${language}" 279 "green"
			fi
			print_simple_separator
			if [[ -n "${enterprise_mode}" ]]; then
				language_strings "${language}" 521
			else
				language_strings "${language}" 266
			fi
			print_simple_separator
		fi
		option_counter=$((option_counter + 1))
		if [[ ${#option_counter} -eq 1 ]]; then spaceiface="  "; else spaceiface=" "; fi
		set_chipset "${item}"
		echo -ne "${option_counter}.${spaceiface}${item} "
		if [[ -z "${chipset}" ]]; then
			language_strings "${language}" 245 "blue"
		else
			if [[ "${is_rtl_language}" -eq 1 ]]; then
				echo -e "${blue_color}// ${normal_color}${chipset} ${yellow_color}:Chipset${normal_color}"
			else
				echo -e "${blue_color}// ${yellow_color}Chipset:${normal_color} ${chipset}"
			fi
		fi
	done

	if [[ "${option_counter}" -eq 0 ]]; then
		if [[ -n "${enterprise_mode}" ]]; then
			return_to_enterprise_main_menu=1
		elif [[ -z "${enterprise_mode}" ]] && [[ -n "${et_mode}" ]]; then
			return_to_et_main_menu=1
			return_to_et_main_menu_from_beef=1
		fi
		echo
		if [[ "${1}" = "dos_pursuit_mode" ]]; then
			language_strings "${language}" 510 "red"
		elif [[ "${1}" = "internet" ]]; then
			language_strings "${language}" 280 "red"
		fi
		language_strings "${language}" 115 "read"
		return 1
	fi

	if [[ ${option_counter: -1} -eq 9 ]]; then spaceiface+=" "; fi
	print_hint

	read -rp "> " secondary_iface
	if [[ "${secondary_iface}" -eq 0 ]] 2>/dev/null; then
		if [[ -n "${enterprise_mode}" ]]; then
			return_to_enterprise_main_menu=1
		elif [[ -z "${enterprise_mode}" ]] && [[ -n "${et_mode}" ]]; then
			return_to_et_main_menu=1
			return_to_et_main_menu_from_beef=1
		fi
		return 1
	elif [[ ! ${secondary_iface} =~ ^[[:digit:]]+$ ]] || \
	     ((secondary_iface < 1 || secondary_iface > option_counter)); then
		if [[ "${1}" = "dos_pursuit_mode" ]]; then
			invalid_secondary_iface_selected "dos_pursuit_mode"
		else
			invalid_secondary_iface_selected "internet"
		fi
	else
		option_counter2=0
		for item2 in "${secondary_ifaces[@]}"; do
			option_counter2=$((option_counter2 + 1))
			if [[ "${secondary_iface}" = "${option_counter2}" ]]; then
				if [[ "${1}" = "dos_pursuit_mode" ]]; then
					secondary_wifi_interface=${item2}
					secondary_phy_interface=$(physical_interface_finder "${secondary_wifi_interface}")
					check_interface_supported_bands "${secondary_phy_interface}" "secondary_wifi_interface"
				elif [[ "${1}" = "internet" ]]; then
					internet_interface=${item2}
				fi
				break
			fi
		done
		return 0
	fi
}

# ============================================================================
# Show status for both dual-interface and single-interface modes.
# ============================================================================
function airgeddon_cli_multint_override_print_iface_selected() {

	debug_print

	if [[ -z "${interface}" ]]; then
		language_strings "${language}" 41 "red"
		echo
		language_strings "${language}" 115 "read"
		select_interface
	else
		if [[ "${multint_enabled}" -eq 1 ]]; then
			check_interface_mode "${multint_ap_interface}"
			if [[ "${ifacemode}" = "(Non wifi adapter)" ]]; then
				language_strings "${language}" 42 "blue"
			else
				language_strings "${language}" "climult_iface_ap_status" "blue"
			fi
			check_interface_mode "${multint_deauth_interface}"
			if [[ "${ifacemode}" = "(Non wifi adapter)" ]]; then
				language_strings "${language}" 42 "blue"
			else
				language_strings "${language}" "climult_iface_deauth_status" "blue"
			fi
		else
			check_interface_mode "${interface}"
			if [[ "${ifacemode}" = "(Non wifi adapter)" ]]; then
				language_strings "${language}" 42 "blue"
			else
				language_strings "${language}" 514 "blue"
			fi
		fi
	fi
}

# ============================================================================
# Override start from tmux
# ============================================================================
function airgeddon_cli_multint_override_start_airgeddon_from_tmux() {

	debug_print

	tmux rename-window -t "${session_name}" "${tmux_main_window}"
	tmux send-keys -t "${session_name}:${tmux_main_window}" "clear;cd ${scriptfolder};bash ${scriptname} true ${airgeddon_uid}" ENTER
	sleep 0.2
	if [ "${1}" = "normal" ]; then
		tmux attach -t "${session_name}"
	else
		tmux switch-client -t "${session_name}"
	fi
}

# ============================================================================
# Override create tmux session
# ============================================================================
function airgeddon_cli_multint_override_create_tmux_session() {

	debug_print

	session_name="${1}"

	if [ "${2}" = "true" ]; then
		tmux new-session -d -s "${1}"
		start_airgeddon_from_tmux "normal" "${3}"
	else
		tmux new-session -d -s "${1}"
		start_airgeddon_from_tmux "nested" "${3}"
	fi
}

# ============================================================================
# Override transfer to tmux
# ============================================================================
function airgeddon_cli_multint_override_transfer_to_tmux() {

	debug_print

	if ! check_inside_tmux; then
		create_tmux_session "${session_name}" "true" "${1}"
	else
		local active_session
		active_session=$(tmux display-message -p '#S')
		if [ "${active_session}" != "${session_name}" ]; then
			tmux_error=1
		fi
	fi
}


function airgeddon_cli_multint_posthook_managed_option() {
	multint_deauth_interface="${interface}"
	return 0
}

function airgeddon_cli_multint_posthook_monitor_option() {
	multint_deauth_interface="${interface}"
	return 0
}

# ============================================================================
# Prehook hookable_for_languages
# ============================================================================
#shellcheck disable=SC1111
function airgeddon_cli_multint_prehook_hookable_for_languages() {

	arr["ENGLISH","climult_sel_ap"]="Select an interface for AP (Master Mode):"
	arr["SPANISH","climult_sel_ap"]="Selecciona una interfaz para AP (Master Mode):"
	arr["FRENCH","climult_sel_ap"]="\${pending_of_translation} Sélectionnez une interface pour AP (Master Mode):"
	arr["CATALAN","climult_sel_ap"]="\${pending_of_translation} Seleccioneu una interfície per a AP (Master Mode):"
	arr["PORTUGUESE","climult_sel_ap"]="\${pending_of_translation} Selecione uma interface para AP (Master Mode):"
	arr["RUSSIAN","climult_sel_ap"]="\${pending_of_translation} Выберите интерфейс для AP (Master Mode):"
	arr["GREEK","climult_sel_ap"]="\${pending_of_translation} Επιλέξτε μια διεπαφή για AP (Master Mode):"
	arr["ITALIAN","climult_sel_ap"]="\${pending_of_translation} Seleziona un'interfaccia per AP (Master Mode):"
	arr["POLISH","climult_sel_ap"]="\${pending_of_translation} Wybierz interfejs dla AP (Master Mode):"
	arr["GERMAN","climult_sel_ap"]="\${pending_of_translation} Wählen Sie eine Schnittstelle für AP (Master Mode) aus:"
	arr["TURKISH","climult_sel_ap"]="\${pending_of_translation} AP için bir arayüz seçin (Master Mode):"
	arr["ARABIC","climult_sel_ap"]="\${pending_of_translation} حدد واجهة لـ AP (Master Mode):"
	arr["CHINESE","climult_sel_ap"]="\${pending_of_translation} 选择一个AP（Master Mode）的接口："

	arr["ENGLISH","climult_sel_deauth"]="Select an interface for Deauth (Monitor Mode):"
	arr["SPANISH","climult_sel_deauth"]="Selecciona una interfaz para Deauth (Monitor Mode):"
	arr["FRENCH","climult_sel_deauth"]="\${pending_of_translation} Sélectionnez une interface pour DeAuth (Monitor Mode):"
	arr["CATALAN","climult_sel_deauth"]="\${pending_of_translation} Seleccioneu una interfície per a DeAuth (Monitor Mode):"
	arr["PORTUGUESE","climult_sel_deauth"]="\${pending_of_translation} Selecione uma interface para Deauth (Monitor Mode):"
	arr["RUSSIAN","climult_sel_deauth"]="\${pending_of_translation} Выберите интерфейс для Deauth (Monitor Mode):"
	arr["GREEK","climult_sel_deauth"]="\${pending_of_translation} Επιλέξτε μια διεπαφή για Deauth (Monitor Mode):"
	arr["ITALIAN","climult_sel_deauth"]="\${pending_of_translation} Seleziona un'interfaccia per Deauth (Monitor Mode):"
	arr["POLISH","climult_sel_deauth"]="\${pending_of_translation} Wybierz interfejs Deauth (Monitor Mode):"
	arr["GERMAN","climult_sel_deauth"]="\${pending_of_translation} Wählen Sie eine Schnittstelle für Deauth (Monitor Mode) aus:"
	arr["TURKISH","climult_sel_deauth"]="\${pending_of_translation} Deauth için bir arayüz seçin (Monitor Mode):"
	arr["ARABIC","climult_sel_deauth"]="\${pending_of_translation} حدد واجهة لـ Deauth (Monitor Mode):"
	arr["CHINESE","climult_sel_deauth"]="\${pending_of_translation} 选择Deauth（Monitor Mode）的接口："

	arr["ENGLISH","climult_err_same_int"]="You can't select the same interface twice"
	arr["SPANISH","climult_err_same_int"]="No puedes seleccionar la misma interfaz dos veces"
	arr["FRENCH","climult_err_same_int"]="\${pending_of_translation} Vous ne pouvez pas sélectionner la même interface deux fois"
	arr["CATALAN","climult_err_same_int"]="\${pending_of_translation} No podeu seleccionar la mateixa interfície dues vegades"
	arr["PORTUGUESE","climult_err_same_int"]="\${pending_of_translation} Você não pode selecionar a mesma interface duas vezes"
	arr["RUSSIAN","climult_err_same_int"]="\${pending_of_translation} Вы не можете выбрать один и тот же интерфейс дважды"
	arr["GREEK","climult_err_same_int"]="\${pending_of_translation} Δεν μπορείτε να επιλέξετε την ίδια διεπαφή δύο φορές"
	arr["ITALIAN","climult_err_same_int"]="\${pending_of_translation} Non è possibile selezionare la stessa interfaccia due volte"
	arr["POLISH","climult_err_same_int"]="\${pending_of_translation} Nie możesz dwa razy wybrać tego samego interfejsu"
	arr["GERMAN","climult_err_same_int"]="\${pending_of_translation} Sie können dieselbe Schnittstelle nicht zweimal auswählen"
	arr["TURKISH","climult_err_same_int"]="\${pending_of_translation} Aynı arayüzü iki kez seçemezsiniz"
	arr["ARABIC","climult_err_same_int"]="\${pending_of_translation} لا يمكنك تحديد الواجهة نفسها مرتين"
	arr["CHINESE","climult_err_same_int"]="\${pending_of_translation} 您不能两次选择相同的界面"

	arr["ENGLISH","climult_iface_ap_status"]="AP Master Mode interface: \${pink_color}\${multint_ap_interface}\${blue_color} selected. Mode: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["SPANISH","climult_iface_ap_status"]="Interfaz AP Master Mode: \${pink_color}\${multint_ap_interface}\${blue_color} seleccionado. Modo: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["FRENCH","climult_iface_ap_status"]="\${pending_of_translation} Interface AP Master Mode: \${pink_color}\${multint_ap_interface}\${blue_color} sélectionnée. Mode: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["CATALAN","climult_iface_ap_status"]="\${pending_of_translation} Interfície AP Master Mode: \${pink_color}\${multint_ap_interface}\${blue_color} seleccionat. Mode: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["PORTUGUESE","climult_iface_ap_status"]="\${pending_of_translation} Interface AP Master Mode: \${pink_color}\${multint_ap_interface}\${blue_color} selecionado. Modo: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["RUSSIAN","climult_iface_ap_status"]="\${pending_of_translation} Интерфейс AP Master Mode: \${pink_color}\${multint_ap_interface}\${blue_color} выбран. Режим: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["GREEK","climult_iface_ap_status"]="\${pending_of_translation} AP Master Mode διεπαφή: \${pink_color}\${multint_ap_interface}\${blue_color} επιλεγμένη. Λειτουργία: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["ITALIAN","climult_iface_ap_status"]="\${pending_of_translation} Interfaccia AP Master Mode: \${pink_color}\${multint_ap_interface}\${blue_color} selezionato. Modalità: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["POLISH","climult_iface_ap_status"]="\${pending_of_translation} Interfejs AP Master Mode: \${pink_color}\${multint_ap_interface}\${blue_color} wybrany. Tryb: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["GERMAN","climult_iface_ap_status"]="\${pending_of_translation} AP Master-Mode: \${pink_color}\${multint_ap_interface}\${blue_color} ausgewählt. Modus: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["TURKISH","climult_iface_ap_status"]="\${pending_of_translation} AP Master Mode: \${pink_color}\${multint_ap_interface}\${blue_color} seçildi. Mod: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["ARABIC","climult_iface_ap_status"]="\${pending_of_translation} واجهة AP الرئيسية: \${pink_color}\${multint_ap_interface}\${blue_color} محدد. الوضع: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"
	arr["CHINESE","climult_iface_ap_status"]="\${pending_of_translation} AP主模式接口: \${pink_color}\${multint_ap_interface}\${blue_color} 已选。模式: \${pink_color}\${ifacemode}\${blue_color}\${normal_color}"

	arr["ENGLISH","climult_iface_deauth_status"]="Deauth Monitor Mode interface: \${pink_color}\${multint_deauth_interface}\${blue_color} selected. Mode: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["SPANISH","climult_iface_deauth_status"]="Interfaz Deauth Monitor Mode: \${pink_color}\${multint_deauth_interface}\${blue_color} seleccionado. Modo: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["FRENCH","climult_iface_deauth_status"]="\${pending_of_translation} Interface Deauth Monitor Mode: \${pink_color}\${multint_deauth_interface}\${blue_color} sélectionnée. Mode: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["CATALAN","climult_iface_deauth_status"]="\${pending_of_translation} Interfície Deauth Monitor Mode: \${pink_color}\${multint_deauth_interface}\${blue_color} seleccionat. Mode: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["PORTUGUESE","climult_iface_deauth_status"]="\${pending_of_translation} Interface Deauth Monitor Mode: \${pink_color}\${multint_deauth_interface}\${blue_color} selecionado. Modo: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["RUSSIAN","climult_iface_deauth_status"]="\${pending_of_translation} Интерфейс Deauth Monitor Mode: \${pink_color}\${multint_deauth_interface}\${blue_color} выбран. Режим: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["GREEK","climult_iface_deauth_status"]="\${pending_of_translation} Deauth Monitor Mode διεπαφή: \${pink_color}\${multint_deauth_interface}\${blue_color} επιλεγμένη. Λειτουργία: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["ITALIAN","climult_iface_deauth_status"]="\${pending_of_translation} Interfaccia Deauth Monitor Mode: \${pink_color}\${multint_deauth_interface}\${blue_color} selezionato. Modalità: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["POLISH","climult_iface_deauth_status"]="\${pending_of_translation} Interfejs Deauth Monitor Mode: \${pink_color}\${multint_deauth_interface}\${blue_color} wybrany. Tryb: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["GERMAN","climult_iface_deauth_status"]="\${pending_of_translation} Deauth Monitor-Mode: \${pink_color}\${multint_deauth_interface}\${blue_color} ausgewählt. Modus: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["TURKISH","climult_iface_deauth_status"]="\${pending_of_translation} Deauth Monitor Mode: \${pink_color}\${multint_deauth_interface}\${blue_color} seçildi. Mod: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["ARABIC","climult_iface_deauth_status"]="\${pending_of_translation} واجهة Deauth للمراقبة: \${pink_color}\${multint_deauth_interface}\${blue_color} محدد. الوضع: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"
	arr["CHINESE","climult_iface_deauth_status"]="\${pending_of_translation} Deauth监控模式接口: \${pink_color}\${multint_deauth_interface}\${blue_color} 已选。模式: \${pink_color}\${ifacemode_deauth}\${blue_color}\${normal_color}"

	arr["ENGLISH","climult_err_invalid_bssid"]="Invalid BSSID. Quitting..."
	arr["SPANISH","climult_err_invalid_bssid"]="BSSID no válido. Saliendo..."
	arr["FRENCH","climult_err_invalid_bssid"]="\${pending_of_translation} BSSID invalide. Sortie..."
	arr["CATALAN","climult_err_invalid_bssid"]="\${pending_of_translation} BSSID no vàlid. Sortint..."
	arr["PORTUGUESE","climult_err_invalid_bssid"]="\${pending_of_translation} BSSID inválido. Saindo..."
	arr["RUSSIAN","climult_err_invalid_bssid"]="\${pending_of_translation} Недопустимый BSSID. Выход..."
	arr["GREEK","climult_err_invalid_bssid"]="\${pending_of_translation} Μη έγκυρο BSSID. Έξοδος..."
	arr["ITALIAN","climult_err_invalid_bssid"]="\${pending_of_translation} BSSID non valido. Uscita..."
	arr["POLISH","climult_err_invalid_bssid"]="\${pending_of_translation} Nieprawidłowy BSSID. Kończenie..."
	arr["GERMAN","climult_err_invalid_bssid"]="\${pending_of_translation} Ungültige BSSID. Beenden..."
	arr["TURKISH","climult_err_invalid_bssid"]="\${pending_of_translation} Geçersiz BSSID. Çıkılıyor..."
	arr["ARABIC","climult_err_invalid_bssid"]="\${pending_of_translation} ...جارٍ الخروج. BSSID غير صالح"
	arr["CHINESE","climult_err_invalid_bssid"]="\${pending_of_translation} BSSID 无效。正在退出..."

	arr["ENGLISH","climult_err_invalid_target_vals"]="Invalid ESSID/Channel/Encryption. Quitting..."
	arr["SPANISH","climult_err_invalid_target_vals"]="ESSID/Canal/Cifrado no válido. Saliendo..."
	arr["FRENCH","climult_err_invalid_target_vals"]="\${pending_of_translation} ESSID/Canal/Chiffrement invalide. Sortie..."
	arr["CATALAN","climult_err_invalid_target_vals"]="\${pending_of_translation} ESSID/Canal/Xifrat no vàlid. Sortint..."
	arr["PORTUGUESE","climult_err_invalid_target_vals"]="\${pending_of_translation} ESSID/Canal/Criptografia inválido. Saindo..."
	arr["RUSSIAN","climult_err_invalid_target_vals"]="\${pending_of_translation} Недопустимые ESSID/Канал/Шифрование. Выход..."
	arr["GREEK","climult_err_invalid_target_vals"]="\${pending_of_translation} Μη έγκυρο ESSID/Κανάλι/Κρυπτογράφηση. Έξοδος..."
	arr["ITALIAN","climult_err_invalid_target_vals"]="\${pending_of_translation} ESSID/Canale/Cifratura non valido. Uscita..."
	arr["POLISH","climult_err_invalid_target_vals"]="\${pending_of_translation} Nieprawidłowy ESSID/Kanał/Szyfrowanie. Kończenie..."
	arr["GERMAN","climult_err_invalid_target_vals"]="\${pending_of_translation} Ungültige ESSID/Kanal/Verschlüsselung. Beenden..."
	arr["TURKISH","climult_err_invalid_target_vals"]="\${pending_of_translation} Geçersiz ESSID/Kanal/Şifreleme. Çıkılıyor..."
	arr["ARABIC","climult_err_invalid_target_vals"]="\${pending_of_translation} ...جارٍ الخروج. ESSID/القناة/التشفير غير صالح"
	arr["CHINESE","climult_err_invalid_target_vals"]="\${pending_of_translation} ESSID/信道/加密 无效。正在退出..."

	arr["ENGLISH","climult_err_no_handshake"]="Handshake file not specified. Quitting..."
	arr["SPANISH","climult_err_no_handshake"]="Archivo de handshake no especificado. Saliendo..."
	arr["FRENCH","climult_err_no_handshake"]="\${pending_of_translation} Fichier de handshake non spécifié. Sortie..."
	arr["CATALAN","climult_err_no_handshake"]="\${pending_of_translation} Fitxer de handshake no especificat. Sortint..."
	arr["PORTUGUESE","climult_err_no_handshake"]="\${pending_of_translation} Arquivo de handshake não especificado. Saindo..."
	arr["RUSSIAN","climult_err_no_handshake"]="\${pending_of_translation} Файл handshake не указан. Выход..."
	arr["GREEK","climult_err_no_handshake"]="\${pending_of_translation} Το αρχείο handshake δεν καθορίστηκε. Έξοδος..."
	arr["ITALIAN","climult_err_no_handshake"]="\${pending_of_translation} File di handshake non specificato. Uscita..."
	arr["POLISH","climult_err_no_handshake"]="\${pending_of_translation} Plik handshake nie został określony. Kończenie..."
	arr["GERMAN","climult_err_no_handshake"]="\${pending_of_translation} Handshake-Datei nicht angegeben. Beenden..."
	arr["TURKISH","climult_err_no_handshake"]="\${pending_of_translation} Handshake dosyası belirtilmedi. Çıkılıyor..."
	arr["ARABIC","climult_err_no_handshake"]="\${pending_of_translation} ...جارٍ الخروج. لم يتم تحديد ملف handshake"
	arr["CHINESE","climult_err_no_handshake"]="\${pending_of_translation} 未指定 handshake 文件。正在退出..."

	arr["ENGLISH","climult_err_no_ap_iface"]="No AP interface specified (--ap-interface). Quitting..."
	arr["SPANISH","climult_err_no_ap_iface"]="No se ha especificado interfaz AP (--ap-interface). Saliendo..."
	arr["FRENCH","climult_err_no_ap_iface"]="\${pending_of_translation} Aucune interface AP spécifiée (--ap-interface). Sortie..."
	arr["CATALAN","climult_err_no_ap_iface"]="\${pending_of_translation} No s'ha especificat cap interfície AP (--ap-interface). Sortint..."
	arr["PORTUGUESE","climult_err_no_ap_iface"]="\${pending_of_translation} Nenhuma interface AP especificada (--ap-interface). Saindo..."
	arr["RUSSIAN","climult_err_no_ap_iface"]="\${pending_of_translation} Интерфейс AP не указан (--ap-interface). Выход..."
	arr["GREEK","climult_err_no_ap_iface"]="\${pending_of_translation} Δεν έχει καθοριστεί διεπαφή AP (--ap-interface). Έξοδος..."
	arr["ITALIAN","climult_err_no_ap_iface"]="\${pending_of_translation} Nessuna interfaccia AP specificata (--ap-interface). Uscita..."
	arr["POLISH","climult_err_no_ap_iface"]="\${pending_of_translation} Nie określono interfejsu AP (--ap-interface). Kończenie..."
	arr["GERMAN","climult_err_no_ap_iface"]="\${pending_of_translation} Keine AP-Schnittstelle angegeben (--ap-interface). Beenden..."
	arr["TURKISH","climult_err_no_ap_iface"]="\${pending_of_translation} AP arayüzü belirtilmedi (--ap-interface). Çıkılıyor..."
	arr["ARABIC","climult_err_no_ap_iface"]="\${pending_of_translation} ...جارٍ الخروج. لم يتم تحديد واجهة AP (--ap-interface)"
	arr["CHINESE","climult_err_no_ap_iface"]="\${pending_of_translation} 未指定 AP 接口 (--ap-interface)。正在退出..."

	arr["ENGLISH","climult_err_ap_managed"]="The AP interface (\${multint_ap_interface}) MUST be in Managed mode. Quitting..."
	arr["SPANISH","climult_err_ap_managed"]="La interfaz AP (\${multint_ap_interface}) DEBE estar en modo Managed. Saliendo..."
	arr["FRENCH","climult_err_ap_managed"]="\${pending_of_translation} L'interface AP (\${multint_ap_interface}) DOIT être en mode Managed. Sortie..."
	arr["CATALAN","climult_err_ap_managed"]="\${pending_of_translation} La interfície AP (\${multint_ap_interface}) HA d'estar en mode Managed. Sortint..."
	arr["PORTUGUESE","climult_err_ap_managed"]="\${pending_of_translation} A interface AP (\${multint_ap_interface}) DEVE estar em modo Managed. Saindo..."
	arr["RUSSIAN","climult_err_ap_managed"]="\${pending_of_translation} Интерфейс AP (\${multint_ap_interface}) ДОЛЖЕН быть в режиме Managed. Выход..."
	arr["GREEK","climult_err_ap_managed"]="\${pending_of_translation} Η διεπαφή AP (\${multint_ap_interface}) ΠΡΕΠΕΙ να είναι σε λειτουργία Managed. Έξοδος..."
	arr["ITALIAN","climult_err_ap_managed"]="\${pending_of_translation} L'interfaccia AP (\${multint_ap_interface}) DEVE essere in modalità Managed. Uscita..."
	arr["POLISH","climult_err_ap_managed"]="\${pending_of_translation} Interfejs AP (\${multint_ap_interface}) MUSI być w trybie Managed. Kończenie..."
	arr["GERMAN","climult_err_ap_managed"]="\${pending_of_translation} Die AP-Schnittstelle (\${multint_ap_interface}) MUSS im Managed-Modus sein. Beenden..."
	arr["TURKISH","climult_err_ap_managed"]="\${pending_of_translation} AP arayüzü (\${multint_ap_interface}) Managed modunda OLMALIDIR. Çıkılıyor..."
	arr["ARABIC","climult_err_ap_managed"]="\${pending_of_translation} ...جارٍ الخروج. يجب أن تكون واجهة AP (\${multint_ap_interface}) في وضع Managed"
	arr["CHINESE","climult_err_ap_managed"]="\${pending_of_translation} AP 接口 (\${multint_ap_interface}) 必须处于 Managed 模式。正在退出..."

	arr["ENGLISH","climult_err_no_deauth_iface"]="No deauth interface specified (--deauth-interface). Quitting..."
	arr["SPANISH","climult_err_no_deauth_iface"]="No se ha especificado interfaz de deauth (--deauth-interface). Saliendo..."
	arr["FRENCH","climult_err_no_deauth_iface"]="\${pending_of_translation} Aucune interface de deauth spécifiée (--deauth-interface). Sortie..."
	arr["CATALAN","climult_err_no_deauth_iface"]="\${pending_of_translation} No s'ha especificat cap interfície de deauth (--deauth-interface). Sortint..."
	arr["PORTUGUESE","climult_err_no_deauth_iface"]="\${pending_of_translation} Nenhuma interface de deauth especificada (--deauth-interface). Saindo..."
	arr["RUSSIAN","climult_err_no_deauth_iface"]="\${pending_of_translation} Интерфейс deauth не указан (--deauth-interface). Выход..."
	arr["GREEK","climult_err_no_deauth_iface"]="\${pending_of_translation} Δεν έχει καθοριστεί διεπαφή deauth (--deauth-interface). Έξοδος..."
	arr["ITALIAN","climult_err_no_deauth_iface"]="\${pending_of_translation} Nessuna interfaccia deauth specificata (--deauth-interface). Uscita..."
	arr["POLISH","climult_err_no_deauth_iface"]="\${pending_of_translation} Nie określono interfejsu deauth (--deauth-interface). Kończenie..."
	arr["GERMAN","climult_err_no_deauth_iface"]="\${pending_of_translation} Keine deauth-Schnittstelle angegeben (--deauth-interface). Beenden..."
	arr["TURKISH","climult_err_no_deauth_iface"]="\${pending_of_translation} Deauth arayüzü belirtilmedi (--deauth-interface). Çıkılıyor..."
	arr["ARABIC","climult_err_no_deauth_iface"]="\${pending_of_translation} ...جارٍ الخروج. لم يتم تحديد واجهة deauth (--deauth-interface)"
	arr["CHINESE","climult_err_no_deauth_iface"]="\${pending_of_translation} 未指定 deauth 接口 (--deauth-interface)。正在退出..."

	arr["ENGLISH","climult_err_deauth_managed"]="The Deauth interface (\${multint_deauth_interface}) MUST be in Managed mode. Quitting..."
	arr["SPANISH","climult_err_deauth_managed"]="La interfaz de deauth (\${multint_deauth_interface}) DEBE estar en modo Managed. Saliendo..."
	arr["FRENCH","climult_err_deauth_managed"]="\${pending_of_translation} L'interface de deauth (\${multint_deauth_interface}) DOIT être en mode Managed. Sortie..."
	arr["CATALAN","climult_err_deauth_managed"]="\${pending_of_translation} La interfície de deauth (\${multint_deauth_interface}) HA d'estar en mode Managed. Sortint..."
	arr["PORTUGUESE","climult_err_deauth_managed"]="\${pending_of_translation} A interface de deauth (\${multint_deauth_interface}) DEVE estar em modo Managed. Saindo..."
	arr["RUSSIAN","climult_err_deauth_managed"]="\${pending_of_translation} Интерфейс deauth (\${multint_deauth_interface}) ДОЛЖЕН быть в режиме Managed. Выход..."
	arr["GREEK","climult_err_deauth_managed"]="\${pending_of_translation} Η διεπαφή deauth (\${multint_deauth_interface}) ΠΡΕΠΕΙ να είναι σε λειτουργία Managed. Έξοδος..."
	arr["ITALIAN","climult_err_deauth_managed"]="\${pending_of_translation} L'interfaccia deauth (\${multint_deauth_interface}) DEVE essere in modalità Managed. Uscita..."
	arr["POLISH","climult_err_deauth_managed"]="\${pending_of_translation} Interfejs deauth (\${multint_deauth_interface}) MUSI być w trybie Managed. Kończenie..."
	arr["GERMAN","climult_err_deauth_managed"]="\${pending_of_translation} Die deauth-Schnittstelle (\${multint_deauth_interface}) MUSS im Managed-Modus sein. Beenden..."
	arr["TURKISH","climult_err_deauth_managed"]="\${pending_of_translation} Deauth arayüzü (\${multint_deauth_interface}) Managed modunda OLMALIDIR. Çıkılıyor..."
	arr["ARABIC","climult_err_deauth_managed"]="\${pending_of_translation} ...جارٍ الخروج. يجب أن تكون واجهة deauth (\${multint_deauth_interface}) في وضع Managed"
	arr["CHINESE","climult_err_deauth_managed"]="\${pending_of_translation} deauth 接口 (\${multint_deauth_interface}) 必须处于 Managed 模式。正在退出..."

	arr["ENGLISH","climult_err_ap_deauth_same"]="AP interface and deauth interface cannot be the same. Quitting..."
	arr["SPANISH","climult_err_ap_deauth_same"]="La interfaz AP y la interfaz de deauth no pueden ser la misma. Saliendo..."
	arr["FRENCH","climult_err_ap_deauth_same"]="\${pending_of_translation} L'interface AP et l'interface de deauth ne peuvent pas être identiques. Sortie..."
	arr["CATALAN","climult_err_ap_deauth_same"]="\${pending_of_translation} La interfície AP i la interfície de deauth no poden ser la mateixa. Sortint..."
	arr["PORTUGUESE","climult_err_ap_deauth_same"]="\${pending_of_translation} A interface AP e a interface de deauth não podem ser a mesma. Saindo..."
	arr["RUSSIAN","climult_err_ap_deauth_same"]="\${pending_of_translation} Интерфейс AP и интерфейс deauth не могут быть одинаковыми. Выход..."
	arr["GREEK","climult_err_ap_deauth_same"]="\${pending_of_translation} Η διεπαφή AP και η διεπαφή deauth δεν μπορούν να είναι ίδιες. Έξοδος..."
	arr["ITALIAN","climult_err_ap_deauth_same"]="\${pending_of_translation} L'interfaccia AP e l'interfaccia deauth non possono essere la stessa. Uscita..."
	arr["POLISH","climult_err_ap_deauth_same"]="\${pending_of_translation} Interfejs AP i interfejs deauth nie mogą być takie same. Kończenie..."
	arr["GERMAN","climult_err_ap_deauth_same"]="\${pending_of_translation} AP-Schnittstelle und deauth-Schnittstelle können nicht gleich sein. Beenden..."
	arr["TURKISH","climult_err_ap_deauth_same"]="\${pending_of_translation} AP arayüzü ve deauth arayüzü aynı olamaz. Çıkılıyor..."
	arr["ARABIC","climult_err_ap_deauth_same"]="\${pending_of_translation} ...جارٍ الخروج. لا يمكن أن تكون واجهة AP وواجهة deauth متطابقتين"
	arr["CHINESE","climult_err_ap_deauth_same"]="\${pending_of_translation} AP 接口和 deauth 接口不能相同。正在退出..."

	arr["ENGLISH","climult_err_no_iface"]="No interface selected. Quitting..."
	arr["SPANISH","climult_err_no_iface"]="No se ha seleccionado ninguna interfaz. Saliendo..."
	arr["FRENCH","climult_err_no_iface"]="\${pending_of_translation} Aucune interface sélectionnée. Sortie..."
	arr["CATALAN","climult_err_no_iface"]="\${pending_of_translation} No s'ha seleccionat cap interfície. Sortint..."
	arr["PORTUGUESE","climult_err_no_iface"]="\${pending_of_translation} Nenhuma interface selecionada. Saindo..."
	arr["RUSSIAN","climult_err_no_iface"]="\${pending_of_translation} Интерфейс не выбран. Выход..."
	arr["GREEK","climult_err_no_iface"]="\${pending_of_translation} Δεν έχει επιλεγεί διεπαφή. Έξοδος..."
	arr["ITALIAN","climult_err_no_iface"]="\${pending_of_translation} Nessuna interfaccia selezionata. Uscita..."
	arr["POLISH","climult_err_no_iface"]="\${pending_of_translation} Nie wybrano żadnego interfejsu. Kończenie..."
	arr["GERMAN","climult_err_no_iface"]="\${pending_of_translation} Keine Schnittstelle ausgewählt. Beenden..."
	arr["TURKISH","climult_err_no_iface"]="\${pending_of_translation} Herhangi bir arayüz seçilmedi. Çıkılıyor..."
	arr["ARABIC","climult_err_no_iface"]="\${pending_of_translation} ...جارٍ الخروج. لم يتم اختيار أي واجهة"
	arr["CHINESE","climult_err_no_iface"]="\${pending_of_translation} 未选择任何接口。正在退出..."

	arr["ENGLISH","climult_err_iface_managed"]="The selected interface MUST be in Managed mode. Quitting..."
	arr["SPANISH","climult_err_iface_managed"]="La interfaz seleccionada DEBE estar en modo Managed. Saliendo..."
	arr["FRENCH","climult_err_iface_managed"]="\${pending_of_translation} L'interface sélectionnée DOIT être en mode Managed. Sortie..."
	arr["CATALAN","climult_err_iface_managed"]="\${pending_of_translation} La interfície seleccionada HA d'estar en mode Managed. Sortint..."
	arr["PORTUGUESE","climult_err_iface_managed"]="\${pending_of_translation} A interface selecionada DEVE estar em modo Managed. Saindo..."
	arr["RUSSIAN","climult_err_iface_managed"]="\${pending_of_translation} Выбранный интерфейс ДОЛЖЕН быть в режиме Managed. Выход..."
	arr["GREEK","climult_err_iface_managed"]="\${pending_of_translation} Η επιλεγμένη διεπαφή ΠΡΕΠΕΙ να είναι σε λειτουργία Managed. Έξοδος..."
	arr["ITALIAN","climult_err_iface_managed"]="\${pending_of_translation} L'interfaccia selezionata DEVE essere in modalità Managed. Uscita..."
	arr["POLISH","climult_err_iface_managed"]="\${pending_of_translation} Wybrany interfejs MUSI być w trybie Managed. Kończenie..."
	arr["GERMAN","climult_err_iface_managed"]="\${pending_of_translation} Die ausgewählte Schnittstelle MUSS im Managed-Modus sein. Beenden..."
	arr["TURKISH","climult_err_iface_managed"]="\${pending_of_translation} Seçilen arayüz Managed modunda OLMALIDIR. Çıkılıyor..."
	arr["ARABIC","climult_err_iface_managed"]="\${pending_of_translation} ...جارٍ الخروج. يجب أن تكون الواجهة المحددة في وضع Managed"
	arr["CHINESE","climult_err_iface_managed"]="\${pending_of_translation} 所选接口必须处于 Managed 模式。正在退出..."

	arr["ENGLISH","climult_err_invalid_dos"]="Invalid DoS selection. Quitting..."
	arr["SPANISH","climult_err_invalid_dos"]="Selección de DoS no válida. Saliendo..."
	arr["FRENCH","climult_err_invalid_dos"]="\${pending_of_translation} Sélection DoS invalide. Sortie..."
	arr["CATALAN","climult_err_invalid_dos"]="\${pending_of_translation} Selecció de DoS no vàlida. Sortint..."
	arr["PORTUGUESE","climult_err_invalid_dos"]="\${pending_of_translation} Seleção de DoS inválida. Saindo..."
	arr["RUSSIAN","climult_err_invalid_dos"]="\${pending_of_translation} Недопустимый выбор DoS. Выход..."
	arr["GREEK","climult_err_invalid_dos"]="\${pending_of_translation} Μη έγκυρη επιλογή DoS. Έξοδος..."
	arr["ITALIAN","climult_err_invalid_dos"]="\${pending_of_translation} Selezione DoS non valida. Uscita..."
	arr["POLISH","climult_err_invalid_dos"]="\${pending_of_translation} Nieprawidłowy wybór DoS. Kończenie..."
	arr["GERMAN","climult_err_invalid_dos"]="\${pending_of_translation} Ungültige DoS-Auswahl. Beenden..."
	arr["TURKISH","climult_err_invalid_dos"]="\${pending_of_translation} Geçersiz DoS seçimi. Çıkılıyor..."
	arr["ARABIC","climult_err_invalid_dos"]="\${pending_of_translation} ...جارٍ الخروج. اختيار DoS غير صالح"
	arr["CHINESE","climult_err_invalid_dos"]="\${pending_of_translation} DoS 选择无效。正在退出..."

	arr["ENGLISH","climult_err_empty_filename"]="Filename cannot be empty. Quitting..."
	arr["SPANISH","climult_err_empty_filename"]="El nombre de archivo no puede estar vacío. Saliendo..."
	arr["FRENCH","climult_err_empty_filename"]="\${pending_of_translation} Le nom de fichier ne peut pas être vide. Sortie..."
	arr["CATALAN","climult_err_empty_filename"]="\${pending_of_translation} El nom del fitxer no pot estar buit. Sortint..."
	arr["PORTUGUESE","climult_err_empty_filename"]="\${pending_of_translation} O nome do arquivo não pode estar vazio. Saindo..."
	arr["RUSSIAN","climult_err_empty_filename"]="\${pending_of_translation} Имя файла не может быть пустым. Выход..."
	arr["GREEK","climult_err_empty_filename"]="\${pending_of_translation} Το όνομα αρχείου δεν μπορεί να είναι κενό. Έξοδος..."
	arr["ITALIAN","climult_err_empty_filename"]="\${pending_of_translation} Il nome del file non può essere vuoto. Uscita..."
	arr["POLISH","climult_err_empty_filename"]="\${pending_of_translation} Nazwa pliku nie może być pusta. Kończenie..."
	arr["GERMAN","climult_err_empty_filename"]="\${pending_of_translation} Dateiname darf nicht leer sein. Beenden..."
	arr["TURKISH","climult_err_empty_filename"]="\${pending_of_translation} Dosya adı boş olamaz. Çıkılıyor..."
	arr["ARABIC","climult_err_empty_filename"]="\${pending_of_translation} ...جارٍ الخروج. لا يمكن أن يكون اسم الملف فارغًا"
	arr["CHINESE","climult_err_empty_filename"]="\${pending_of_translation} 文件名不能为空。正在退出..."

	arr["ENGLISH","climult_err_file_not_found"]="File not found. Quitting..."
	arr["SPANISH","climult_err_file_not_found"]="Archivo no encontrado. Saliendo..."
	arr["FRENCH","climult_err_file_not_found"]="\${pending_of_translation} Fichier non trouvé. Sortie..."
	arr["CATALAN","climult_err_file_not_found"]="\${pending_of_translation} Fitxer no trobat. Sortint..."
	arr["PORTUGUESE","climult_err_file_not_found"]="\${pending_of_translation} Arquivo não encontrado. Saindo..."
	arr["RUSSIAN","climult_err_file_not_found"]="\${pending_of_translation} Файл не найден. Выход..."
	arr["GREEK","climult_err_file_not_found"]="\${pending_of_translation} Το αρχείο δεν βρέθηκε. Έξοδος..."
	arr["ITALIAN","climult_err_file_not_found"]="\${pending_of_translation} File non trovato. Uscita..."
	arr["POLISH","climult_err_file_not_found"]="\${pending_of_translation} Nie znaleziono pliku. Kończenie..."
	arr["GERMAN","climult_err_file_not_found"]="\${pending_of_translation} Datei nicht gefunden. Beenden..."
	arr["TURKISH","climult_err_file_not_found"]="\${pending_of_translation} Dosya bulunamadı. Çıkılıyor..."
	arr["ARABIC","climult_err_file_not_found"]="\${pending_of_translation} ...جارٍ الخروج. لم يتم العثور على الملف"
	arr["CHINESE","climult_err_file_not_found"]="\${pending_of_translation} 未找到文件。正在退出..."

	arr["ENGLISH","climult_err_no_hsfile"]="No handshake file specified. Quitting..."
	arr["SPANISH","climult_err_no_hsfile"]="No se ha especificado archivo de handshake. Saliendo..."
	arr["FRENCH","climult_err_no_hsfile"]="\${pending_of_translation} Aucun fichier de handshake spécifié. Sortie..."
	arr["CATALAN","climult_err_no_hsfile"]="\${pending_of_translation} No s'ha especificat cap fitxer de handshake. Sortint..."
	arr["PORTUGUESE","climult_err_no_hsfile"]="\${pending_of_translation} Nenhum arquivo de handshake especificado. Saindo..."
	arr["RUSSIAN","climult_err_no_hsfile"]="\${pending_of_translation} Файл handshake не указан. Выход..."
	arr["GREEK","climult_err_no_hsfile"]="\${pending_of_translation} Δεν έχει καθοριστεί αρχείο handshake. Έξοδος..."
	arr["ITALIAN","climult_err_no_hsfile"]="\${pending_of_translation} Nessun file di handshake specificato. Uscita..."
	arr["POLISH","climult_err_no_hsfile"]="\${pending_of_translation} Nie określono pliku handshake. Kończenie..."
	arr["GERMAN","climult_err_no_hsfile"]="\${pending_of_translation} Keine Handshake-Datei angegeben. Beenden..."
	arr["TURKISH","climult_err_no_hsfile"]="\${pending_of_translation} Handshake dosyası belirtilmedi. Çıkılıyor..."
	arr["ARABIC","climult_err_no_hsfile"]="\${pending_of_translation} ...جارٍ الخروج. لم يتم تحديد ملف handshake"
	arr["CHINESE","climult_err_no_hsfile"]="\${pending_of_translation} 未指定 handshake 文件。正在退出..."

	arr["ENGLISH","climult_err_hsfile_missing"]="Handshake file doesn't exist. Quitting..."
	arr["SPANISH","climult_err_hsfile_missing"]="El archivo de handshake no existe. Saliendo..."
	arr["FRENCH","climult_err_hsfile_missing"]="\${pending_of_translation} Le fichier de handshake n'existe pas. Sortie..."
	arr["CATALAN","climult_err_hsfile_missing"]="\${pending_of_translation} El fitxer de handshake no existeix. Sortint..."
	arr["PORTUGUESE","climult_err_hsfile_missing"]="\${pending_of_translation} O arquivo de handshake não existe. Saindo..."
	arr["RUSSIAN","climult_err_hsfile_missing"]="\${pending_of_translation} Файл handshake не существует. Выход..."
	arr["GREEK","climult_err_hsfile_missing"]="\${pending_of_translation} Το αρχείο handshake δεν υπάρχει. Έξοδος..."
	arr["ITALIAN","climult_err_hsfile_missing"]="\${pending_of_translation} Il file di handshake non esiste. Uscita..."
	arr["POLISH","climult_err_hsfile_missing"]="\${pending_of_translation} Plik handshake nie istnieje. Kończenie..."
	arr["GERMAN","climult_err_hsfile_missing"]="\${pending_of_translation} Handshake-Datei existiert nicht. Beenden..."
	arr["TURKISH","climult_err_hsfile_missing"]="\${pending_of_translation} Handshake dosyası mevcut değil. Çıkılıyor..."
	arr["ARABIC","climult_err_hsfile_missing"]="\${pending_of_translation} ...جارٍ الخروج. ملف handshake غير موجود"
	arr["CHINESE","climult_err_hsfile_missing"]="\${pending_of_translation} handshake 文件不存在。正在退出..."

	arr["ENGLISH","climult_err_bssid_hsfile_mismatch"]="BSSID and handshake file doesn't match. Quitting..."
	arr["SPANISH","climult_err_bssid_hsfile_mismatch"]="El BSSID y el archivo de handshake no coinciden. Saliendo..."
	arr["FRENCH","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} Le BSSID et le fichier de handshake ne correspondent pas. Sortie..."
	arr["CATALAN","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} El BSSID i el fitxer de handshake no coincideixen. Sortint..."
	arr["PORTUGUESE","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} O BSSID e o arquivo de handshake não coincidem. Saindo..."
	arr["RUSSIAN","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} BSSID и файл handshake не совпадают. Выход..."
	arr["GREEK","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} Το BSSID και το αρχείο handshake δεν ταιριάζουν. Έξοδος..."
	arr["ITALIAN","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} Il BSSID e il file di handshake non corrispondono. Uscita..."
	arr["POLISH","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} BSSID i plik handshake nie pasują do siebie. Kończenie..."
	arr["GERMAN","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} BSSID und Handshake-Datei stimmen nicht überein. Beenden..."
	arr["TURKISH","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} BSSID ve handshake dosyası eşleşmiyor. Çıkılıyor..."
	arr["ARABIC","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} ...جارٍ الخروج. BSSID وملف handshake غير متطابقين"
	arr["CHINESE","climult_err_bssid_hsfile_mismatch"]="\${pending_of_translation} BSSID 与 handshake 文件不匹配。正在退出..."

	arr["ENGLISH","climult_info_set_monitor_dos"]="Trying to set monitor mode on DoS Pursuit interface..."
	arr["SPANISH","climult_info_set_monitor_dos"]="Intentando establecer modo monitor en la interfaz DoS Pursuit..."
	arr["FRENCH","climult_info_set_monitor_dos"]="\${pending_of_translation} Tentative de mise en mode monitor sur l'interface DoS Pursuit..."
	arr["CATALAN","climult_info_set_monitor_dos"]="\${pending_of_translation} Intentant establir mode monitor a la interfície DoS Pursuit..."
	arr["PORTUGUESE","climult_info_set_monitor_dos"]="\${pending_of_translation} Tentando definir modo monitor na interface DoS Pursuit..."
	arr["RUSSIAN","climult_info_set_monitor_dos"]="\${pending_of_translation} Попытка установить режим мониторинга на интерфейсе DoS Pursuit..."
	arr["GREEK","climult_info_set_monitor_dos"]="\${pending_of_translation} Προσπάθεια ορισμού λειτουργίας monitor στη διεπαφή DoS Pursuit..."
	arr["ITALIAN","climult_info_set_monitor_dos"]="\${pending_of_translation} Tentativo di impostare la modalità monitor sull'interfaccia DoS Pursuit..."
	arr["POLISH","climult_info_set_monitor_dos"]="\${pending_of_translation} Próba ustawienia trybu monitor na interfejsie DoS Pursuit..."
	arr["GERMAN","climult_info_set_monitor_dos"]="\${pending_of_translation} Versuche den Monitor-Modus auf der DoS-Pursuit-Schnittstelle zu setzen..."
	arr["TURKISH","climult_info_set_monitor_dos"]="\${pending_of_translation} DoS Pursuit arayüzünde monitor modu ayarlanmaya çalışılıyor..."
	arr["ARABIC","climult_info_set_monitor_dos"]="\${pending_of_translation} ...جارٍ محاولة تعيين وضع monitor على واجهة DoS Pursuit"
	arr["CHINESE","climult_info_set_monitor_dos"]="\${pending_of_translation} 正在尝试在 DoS Pursuit 接口上设置 monitor 模式..."

	arr["ENGLISH","climult_err_dos_monitor"]="The interface for DoS Pursuit mode cannot be set into monitor mode. Quitting..."
	arr["SPANISH","climult_err_dos_monitor"]="La interfaz para modo DoS Pursuit no se puede poner en modo monitor. Saliendo..."
	arr["FRENCH","climult_err_dos_monitor"]="\${pending_of_translation} L'interface pour le mode DoS Pursuit ne peut pas être mise en mode monitor. Sortie..."
	arr["CATALAN","climult_err_dos_monitor"]="\${pending_of_translation} La interfície per al mode DoS Pursuit no es pot posar en mode monitor. Sortint..."
	arr["PORTUGUESE","climult_err_dos_monitor"]="\${pending_of_translation} A interface para o modo DoS Pursuit não pode ser colocada em modo monitor. Saindo..."
	arr["RUSSIAN","climult_err_dos_monitor"]="\${pending_of_translation} Интерфейс для режима DoS Pursuit не может быть переведен в режим мониторинга. Выход..."
	arr["GREEK","climult_err_dos_monitor"]="\${pending_of_translation} Η διεπαφή για λειτουργία DoS Pursuit δεν μπορεί να τεθεί σε λειτουργία monitor. Έξοδος..."
	arr["ITALIAN","climult_err_dos_monitor"]="\${pending_of_translation} L'interfaccia per la modalità DoS Pursuit non può essere impostata in modalità monitor. Uscita..."
	arr["POLISH","climult_err_dos_monitor"]="\${pending_of_translation} Interfejs dla trybu DoS Pursuit nie może zostać ustawiony w trybie monitor. Kończenie..."
	arr["GERMAN","climult_err_dos_monitor"]="\${pending_of_translation} Die Schnittstelle für den DoS-Pursuit-Modus kann nicht in den Monitor-Modus gesetzt werden. Beenden..."
	arr["TURKISH","climult_err_dos_monitor"]="\${pending_of_translation} DoS Pursuit modu için arayüz monitor moduna alınamaz. Çıkılıyor..."
	arr["ARABIC","climult_err_dos_monitor"]="\${pending_of_translation} ...جارٍ الخروج. لا يمكن تعيين واجهة وضع DoS Pursuit إلى وضع monitor"
	arr["CHINESE","climult_err_dos_monitor"]="\${pending_of_translation} DoS Pursuit 模式的接口无法设置为 monitor 模式。正在退出..."

	arr["ENGLISH","climult_err_mutual_excl"]="Cannot use -i/--interface together with --ap-interface/--deauth-interface. Quitting..."
	arr["SPANISH","climult_err_mutual_excl"]="No puedes usar -i/--interface junto con --ap-interface/--deauth-interface. Saliendo..."
	arr["FRENCH","climult_err_mutual_excl"]="\${pending_of_translation} Impossible d'utiliser -i/--interface avec --ap-interface/--deauth-interface. Sortie..."
	arr["CATALAN","climult_err_mutual_excl"]="\${pending_of_translation} No pots usar -i/--interface junt amb --ap-interface/--deauth-interface. Sortint..."
	arr["PORTUGUESE","climult_err_mutual_excl"]="\${pending_of_translation} Não podes usar -i/--interface junto com --ap-interface/--deauth-interface. Saindo..."
	arr["RUSSIAN","climult_err_mutual_excl"]="\${pending_of_translation} Нельзя использовать -i/--interface вместе с --ap-interface/--deauth-interface. Выход..."
	arr["GREEK","climult_err_mutual_excl"]="\${pending_of_translation} Δεν μπορείς να χρησιμοποιήσεις -i/--interface μαζί με --ap-interface/--deauth-interface. Έξοδος..."
	arr["ITALIAN","climult_err_mutual_excl"]="\${pending_of_translation} Non puoi usare -i/--interface insieme a --ap-interface/--deauth-interface. Uscita..."
	arr["POLISH","climult_err_mutual_excl"]="\${pending_of_translation} Nie możesz używać -i/--interface razem z --ap-interface/--deauth-interface. Kończenie..."
	arr["GERMAN","climult_err_mutual_excl"]="\${pending_of_translation} -i/--interface kann nicht zusammen mit --ap-interface/--deauth-interface verwendet werden. Beenden..."
	arr["TURKISH","climult_err_mutual_excl"]="\${pending_of_translation} -i/--interface ile --ap-interface/--deauth-interface birlikte kullanılamaz. Çıkılıyor..."
	arr["ARABIC","climult_err_mutual_excl"]="\${pending_of_translation} ...جارٍ الخروج. لا يمكن استخدام -i/--interface مع --ap-interface/--deauth-interface معًا"
	arr["CHINESE","climult_err_mutual_excl"]="\${pending_of_translation} 不能将 -i/--interface 与 --ap-interface/--deauth-interface 一起使用。正在退出..."

	arr["ENGLISH","climult_err_ap_requires_deauth"]="--ap-interface requires --deauth-interface to also be specified. Quitting..."
	arr["SPANISH","climult_err_ap_requires_deauth"]="--ap-interface requiere que también se especifique --deauth-interface. Saliendo..."
	arr["FRENCH","climult_err_ap_requires_deauth"]="\${pending_of_translation} --ap-interface nécessite que --deauth-interface soit également spécifié. Sortie..."
	arr["CATALAN","climult_err_ap_requires_deauth"]="\${pending_of_translation} --ap-interface requereix que també s'especifiqui --deauth-interface. Sortint..."
	arr["PORTUGUESE","climult_err_ap_requires_deauth"]="\${pending_of_translation} --ap-interface requer que --deauth-interface também seja especificada. Saindo..."
	arr["RUSSIAN","climult_err_ap_requires_deauth"]="\${pending_of_translation} --ap-interface требует, чтобы также был указан --deauth-interface. Выход..."
	arr["GREEK","climult_err_ap_requires_deauth"]="\${pending_of_translation} Το --ap-interface απαιτεί να οριστεί επίσης το --deauth-interface. Έξοδος..."
	arr["ITALIAN","climult_err_ap_requires_deauth"]="\${pending_of_translation} --ap-interface richiede che venga specificato anche --deauth-interface. Uscita..."
	arr["POLISH","climult_err_ap_requires_deauth"]="\${pending_of_translation} --ap-interface wymaga również określenia --deauth-interface. Kończenie..."
	arr["GERMAN","climult_err_ap_requires_deauth"]="\${pending_of_translation} --ap-interface erfordert, dass auch --deauth-interface angegeben wird. Beenden..."
	arr["TURKISH","climult_err_ap_requires_deauth"]="\${pending_of_translation} --ap-interface kullanımı için --deauth-interface de belirtilmelidir. Çıkılıyor..."
	arr["ARABIC","climult_err_ap_requires_deauth"]="\${pending_of_translation} ...جارٍ الخروج. يتطلب --ap-interface أيضًا تحديد --deauth-interface"
	arr["CHINESE","climult_err_ap_requires_deauth"]="\${pending_of_translation} --ap-interface 需要同时指定 --deauth-interface。正在退出..."

	arr["ENGLISH","climult_err_deauth_requires_ap"]="--deauth-interface requires --ap-interface to also be specified. Quitting..."
	arr["SPANISH","climult_err_deauth_requires_ap"]="--deauth-interface requiere que también se especifique --ap-interface. Saliendo..."
	arr["FRENCH","climult_err_deauth_requires_ap"]="\${pending_of_translation} --deauth-interface nécessite que --ap-interface soit également spécifié. Sortie..."
	arr["CATALAN","climult_err_deauth_requires_ap"]="\${pending_of_translation} --deauth-interface requereix que també s'especifiqui --ap-interface. Sortint..."
	arr["PORTUGUESE","climult_err_deauth_requires_ap"]="\${pending_of_translation} --deauth-interface requer que --ap-interface também seja especificada. Saindo..."
	arr["RUSSIAN","climult_err_deauth_requires_ap"]="\${pending_of_translation} --deauth-interface требует, чтобы также был указан --ap-interface. Выход..."
	arr["GREEK","climult_err_deauth_requires_ap"]="\${pending_of_translation} Το --deauth-interface απαιτεί να οριστεί επίσης το --ap-interface. Έξοδος..."
	arr["ITALIAN","climult_err_deauth_requires_ap"]="\${pending_of_translation} --deauth-interface richiede che venga specificato anche --ap-interface. Uscita..."
	arr["POLISH","climult_err_deauth_requires_ap"]="\${pending_of_translation} --deauth-interface wymaga również określenia --ap-interface. Kończenie..."
	arr["GERMAN","climult_err_deauth_requires_ap"]="\${pending_of_translation} --deauth-interface erfordert, dass auch --ap-interface angegeben wird. Beenden..."
	arr["TURKISH","climult_err_deauth_requires_ap"]="\${pending_of_translation} --deauth-interface kullanımı için --ap-interface de belirtilmelidir. Çıkılıyor..."
	arr["ARABIC","climult_err_deauth_requires_ap"]="\${pending_of_translation} ...جارٍ الخروج. يتطلب --deauth-interface أيضًا تحديد --ap-interface"
	arr["CHINESE","climult_err_deauth_requires_ap"]="\${pending_of_translation} --deauth-interface 需要同时指定 --ap-interface。正在退出..."
}

# ============================================================================
# Two new long-only switches are added for dual-adapter mode:
#   --ap-interface <interface>     : AP card (master mode)
#   --deauth-interface <interface> : Deauth card (monitor mode)
#
# -i/--interface (single VIF card) and --ap-interface/--deauth-interface
# are mutually exclusive. Using both will cause a validation error on launch.
# ============================================================================

if [ "$#" -gt 0 ]; then
	airgeddon_cli_skip=0

	if [[ $(ls "${scriptfolder}" | grep "${scriptname}") == "" ]]; then
		airgeddon_cli_multint_get_absolute_script_path
	else
		airgeddon_cli_absolute_script_path="${scriptfolder}"
	fi

	if [ -z "${airgeddon_cli_targets_default_path}" ]; then
		airgeddon_cli_targets_default_path="${airgeddon_cli_absolute_script_path}"plugins/captured_handshakes/targets/
	fi

	if ! airgeddon_cli_arguments=$(getopt -a \
		--options="ab:c:de:f:h:i:l:mp:tuv" \
		--longoptions="advportal,ap-interface:,bssid:,channel:,cplang:,cl:,debug,deauth-interface:,dos:,dp:,enc:,essid:,file:,hsfile:,interface:,ms,nk,tmux,usage,version" \
		--name="airgeddon v${airgeddon_version}" -- "$@"
	); then
		airgeddon_cli_multint_print_usage
		exit
	fi

	eval set -- "$airgeddon_cli_arguments"

	while [ "$1" != "" ] && [ "$1" != "--" ]; do
		case "$1" in
			-a|--advportal)
				advanced_captive_portal=1
				;;
			--ap-interface)
				multint_ap_interface="${2}"
				shift
				;;
			-b|--bssid)
				if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
					bssid="${2}"
				fi
				shift
				;;
			-c|--channel)
				if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
					channel="${2}"
				fi
				shift
				;;
			--cl)
				airgeddon_cli_multint_manage_captive_portal_log
				et_captive_portal_logpath="${2:-$default_et_captive_portal_logpath}"
				shift
				;;
			-d|--debug)
				AIRGEDDON_DEBUG_MODE="true"
				;;
			--deauth-interface)
				multint_deauth_interface="${2}"
				shift
				;;
			--dos)
				case "${2}" in
					1) et_dos_attack="${mdk_command}" ;;
					2) et_dos_attack="Aireplay" ;;
					3) et_dos_attack="Auth DoS" ;;
					*)
						language_strings "${language}" "climult_err_invalid_dos" "red"
						exit
						;;
				esac
				shift
				;;
			-e|--essid)
				if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
					essid="${2}"
				fi
				shift
				;;
			--enc)
				if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
					enc="${2:-WPA2}"
				fi
				shift
				;;
			-f|--file)
				if [ -z "${2}" ]; then
					language_strings "${language}" "climult_err_empty_filename" "red"
					exit
				fi

				if [ -f "${2}" ]; then
					airgeddon_cli_target_file="${2##*/}"
					dir="${2%/*}"
					if [ "${dir}" = "${2}" ]; then
						airgeddon_cli_targets_default_path="./"
					else
						airgeddon_cli_targets_default_path="${dir%/}/"
					fi

					airgeddon_cli_filemode=1
				else
					if ! check_file_exists "${airgeddon_cli_targets_default_path}${2}"; then
						language_strings "${language}" "climult_err_file_not_found" "red"
						exit
					fi
					airgeddon_cli_target_file="${2}"
					airgeddon_cli_filemode=1
				fi

				airgeddon_cli_multint_read_target_values
				shift
				;;
			-h|--hsfile)
				if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
					if [ -z "${2}" ]; then
						language_strings "${language}" "climult_err_no_hsfile" "red"
					fi
					et_handshake="${2}"
					if ! check_file_exists "${et_handshake}"; then
						language_strings "${language}" "climult_err_hsfile_missing" "red"
						exit
					fi
					if ! check_bssid_in_captured_file "${et_handshake}" "silent" "also_pmkid"; then
						language_strings "${language}" "climult_err_bssid_hsfile_mismatch" "red"
						exit
					fi
				fi
				shift
				;;
			-i|--interface)
				interface="${2}"
				phy_interface=$(physical_interface_finder "${interface}")
				shift
				;;
			-l|--cplang)
				captive_portal_language="${2:-ENGLISH}"
				shift
				;;
			-m|--ms)
				mac_spoofing_desired=1
				shift
				;;
			--nk)
				AIRGEDDON_FORCE_NETWORK_MANAGER_KILLING="false"
				;;
			-p|--dp)
				dos_pursuit_mode=1
				secondary_wifi_interface="${2}"
				airgeddon_cli_multint_secondary_wifi_interface="${secondary_wifi_interface}"
				secondary_phy_interface=$(physical_interface_finder "${secondary_wifi_interface}")
				check_interface_supported_bands "${secondary_phy_interface}" "secondary_wifi_interface"
				if ! check_monitor_enabled "${secondary_wifi_interface}"; then
					language_strings "${language}" "climult_info_set_monitor_dos" "yellow"
					if ! set_mode_without_airmon "${secondary_wifi_interface}" "monitor"; then
						language_strings "${language}" "climult_err_dos_monitor" "red"
						exit
					fi
				fi
				shift
				;;
			-t|--tmux)
				AIRGEDDON_WINDOWS_HANDLING="tmux"
				;;
			-u|--usage)
				airgeddon_cli_multint_print_usage
				exit
				;;
			-v|--version)
				if hash git 2>/dev/null; then
					airgeddon_cli_git_rev=" rev_"$(git rev-parse --short HEAD)"("$(git rev-parse --abbrev-ref HEAD)" branch)"
				fi
				echo "airgeddon v${airgeddon_version}${airgeddon_cli_git_rev}"
				exit
				;;
		esac
		shift
	done
	shift

	# Post-parse: activate dual-adapter mode if both interfaces were given ──
	if [[ -n "${multint_ap_interface}" ]] && [[ -n "${multint_deauth_interface}" ]]; then

		# Mutual exclusion check: -i and --ap/--deauth-interface cannot coexist
		if [[ -n "${interface}" ]]; then
			language_strings "${language}" "climult_err_mutual_excl" "red"
			exit
		fi

		multint_enabled=1

	elif [[ -n "${multint_ap_interface}" ]] && [[ -z "${multint_deauth_interface}" ]]; then
		language_strings "${language}" "climult_err_ap_requires_deauth" "red"
		exit

	elif [[ -z "${multint_ap_interface}" ]] && [[ -n "${multint_deauth_interface}" ]]; then
		language_strings "${language}" "climult_err_deauth_requires_ap" "red"
		exit
	fi
else
	airgeddon_cli_active=0
	airgeddon_cli_skip=1
fi
