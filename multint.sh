#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### GENERIC PLUGIN VARS ######

plugin_name="multint"
plugin_description="Support for dual WiFi adapters on Evil Twin with Captive Portal attack"
plugin_author="xpz3"

#Enabled 1 / Disabled 0 - Set this plugin as enabled - Default value 1
plugin_enabled=1

###### PLUGIN REQUIREMENTS ######

#Set airgeddon versions to apply this plugin (leave blank to set no limits, minimum version recommended is 10.0 on which plugins feature was added)
plugin_minimum_ag_affected_version="11.20"
plugin_maximum_ag_affected_version=""

#Set only one element in the array "*" to affect all distros, otherwise add them one by one with the name which airgeddon uses for that distro (examples "BlackArch", "Parrot", "Kali")
plugin_distros_supported=("*")

function multint_override_select_interface() {

	debug_print

	local interface_menu_band
	local multintcounter=0
	multint_enabled=1
	
	while [ "${multintcounter}" -lt 2 ]
	do
		clear
		language_strings "${language}" 88 "title"
		current_menu="select_interface_menu"
		if [ "${multintcounter}" -eq 0 ]; then
			language_strings "${language}" "multint_text_1" "green"
		else
			language_strings "${language}" "multint_text_2" "green"
		fi
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
				if [[ "${iface}" = "${option_counter2}" ]]; then
					
					if [ "${multintcounter}" -eq 0 ]; then
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
						interface=${item2}
						phy_interface=$(physical_interface_finder "${interface}")
						check_interface_supported_bands "${phy_interface}" "main_wifi_interface"
						interface_mac=$(ip link show "${interface}" | awk '/ether/ {print $2}')
						break
					fi
				fi
			done
		fi
		multintcounter=$((multintcounter + 1))
	done
	if [ "${multint_ap_interface}" = "${multint_deauth_interface}" ]; then
		multint_enabled=0
	fi
}

function multint_override_prepare_et_monitor() {

	debug_print

	disable_rfkill
	if [ "${multint_enabled}" -eq 1 ]; then
		iface_monitor_et_deauth="${multint_deauth_interface}"

		ip link set "${iface_monitor_et_deauth}" down > /dev/null 2>&1
	else
		iface_phy_number=${phy_interface:3:1}
		iface_monitor_et_deauth="mon${iface_phy_number}"

		iw phy "${phy_interface}" interface add "${iface_monitor_et_deauth}" type monitor 2> /dev/null
	fi

	ip link set "${iface_monitor_et_deauth}" up > /dev/null 2>&1
	iw "${iface_monitor_et_deauth}" set channel "${channel}" > /dev/null 2>&1
}

function multint_override_prepare_et_interface() {

	debug_print

	et_initial_state=${ifacemode}
	
	if [ "${multint_enabled}" -eq 1 ]; then
		ifacemode="Managed"
		multint_deauth_interface="${interface}"
		interface="${multint_ap_interface}"
	fi

	if [ "${ifacemode}" != "Managed" ]; then
		check_airmon_compatibility "interface"
		if [ "${interface_airmon_compatible}" -eq 1 ]; then
			new_interface=$(${airmon} stop "${interface}" 2> /dev/null | grep station | head -n 1)
			ifacemode="Managed"
			[[ ${new_interface} =~ \]?([A-Za-z0-9]+)\)?$ ]] && new_interface="${BASH_REMATCH[1]}"

			if [ "${interface}" != "${new_interface}" ]; then
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

function multint_override_restore_et_interface() {

	debug_print

	if [ "${multint_enabled}" -eq 1 ]; then
	
		interface="${multint_deauth_interface}"
		set_mode_without_airmon "${multint_ap_interface}" "managed"
	fi
	echo
	language_strings "${language}" 299 "blue"

	disable_rfkill

	mac_spoofing_desired=0	

	if [ "${et_initial_state}" = "Managed" ]; then
		set_mode_without_airmon "${interface}" "managed"
		ifacemode="Managed"
	else
		if [ "${interface_airmon_compatible}" -eq 1 ]; then
			new_interface=$(${airmon} start "${interface}" 2> /dev/null | grep monitor)
			desired_interface_name=""
			[[ ${new_interface} =~ ^You[[:space:]]already[[:space:]]have[[:space:]]a[[:space:]]([A-Za-z0-9]+)[[:space:]]device ]] && desired_interface_name="${BASH_REMATCH[1]}"
			if [ -n "${desired_interface_name}" ]; then
				echo
				language_strings "${language}" 435 "red"
				language_strings "${language}" 115 "read"
				return
			fi

			ifacemode="Monitor"

			[[ ${new_interface} =~ \]?([A-Za-z0-9]+)\)?$ ]] && new_interface="${BASH_REMATCH[1]}"
			if [ "${interface}" != "${new_interface}" ]; then
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
}

function multint_override_select_secondary_interface() {

	debug_print

	if [ "${return_to_et_main_menu}" -eq 1 ]; then
		return 1
	fi

	if [ "${return_to_enterprise_main_menu}" -eq 1 ]; then
		return 1
	fi

	clear
	if [ -n "${enterprise_mode}" ]; then
		current_menu="enterprise_attacks_menu"
		case ${enterprise_mode} in
			"smooth")
				language_strings "${language}" 522 "title"
			;;
			"noisy")
				language_strings "${language}" 523 "title"
			;;
		esac
	elif [[ -z "${enterprise_mode}" ]] && [[ -z "${et_mode}" ]]; then
		current_menu="dos_attacks_menu"
	elif [[ -z "${enterprise_mode}" ]] && [[ -n "${et_mode}" ]]; then
		current_menu="evil_twin_attacks_menu"
		case ${et_mode} in
			"et_onlyap")
				language_strings "${language}" 270 "title"
			;;
			"et_sniffing")
				language_strings "${language}" 291 "title"
			;;
			"et_sniffing_sslstrip")
				language_strings "${language}" 292 "title"
			;;
			"et_sniffing_sslstrip2")
				language_strings "${language}" 397 "title"
			;;
			"et_captive_portal")
				language_strings "${language}" 293 "title"
			;;
		esac
	fi

	if [ "${1}" = "dos_pursuit_mode" ]; then
		if [ "${multint_enabled}" -eq 1 ]; then
			readarray -t secondary_ifaces < <(iw dev | grep "Interface" | awk '{print $2}' | grep "${interface}" -v | grep "${multint_ap_interface}" -v)
		else
			readarray -t secondary_ifaces < <(iw dev | grep "Interface" | awk '{print $2}' | grep "${interface}" -v)
		fi
	elif [ "${1}" = "internet" ]; then
		if [ "${multint_enabled}" -eq 1 ]; then
			if [ -n "${secondary_wifi_interface}" ]; then
				readarray -t secondary_ifaces < <(ip link | grep -E "^[0-9]+" | cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v | grep "${interface}" -v | grep "${secondary_wifi_interface}" -v | grep "${multint_ap_interface}" -v)
			else
				readarray -t secondary_ifaces < <(ip link | grep -E "^[0-9]+" | cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v | grep "${interface}" -v | grep "${multint_ap_interface}" -v)
			fi
		else
			if [ -n "${secondary_wifi_interface}" ]; then
				readarray -t secondary_ifaces < <(ip link | grep -E "^[0-9]+" | cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v | grep "${interface}" -v | grep "${secondary_wifi_interface}" -v)
			else
				readarray -t secondary_ifaces < <(ip link | grep -E "^[0-9]+" | cut -d ':' -f 2 | awk '{print $1}' | grep -E "^lo$" -v | grep "${interface}" -v)
			fi
		fi
	fi

	if [ ${#secondary_ifaces[@]} -eq 1 ]; then
		if [ "${1}" = "dos_pursuit_mode" ]; then
			secondary_wifi_interface="${secondary_ifaces[0]}"
			secondary_phy_interface=$(physical_interface_finder "${secondary_wifi_interface}")
			check_interface_supported_bands "${secondary_phy_interface}" "secondary_wifi_interface"
		elif [ "${1}" = "internet" ]; then
			internet_interface="${secondary_ifaces[0]}"
		fi

		echo
		language_strings "${language}" 662 "yellow"
		language_strings "${language}" 115 "read"
		return 0
	fi

	option_counter=0
	for item in "${secondary_ifaces[@]}"; do
		if [ ${option_counter} -eq 0 ]; then
			if [ "${1}" = "dos_pursuit_mode" ]; then
				language_strings "${language}" 511 "green"
			elif [ "${1}" = "internet" ]; then
				language_strings "${language}" 279 "green"
			fi
			print_simple_separator
			if [ -n "${enterprise_mode}" ]; then
				language_strings "${language}" 521
			else
				language_strings "${language}" 266
			fi
			print_simple_separator
		fi

		option_counter=$((option_counter + 1))
		if [ ${#option_counter} -eq 1 ]; then
			spaceiface="  "
		else
			spaceiface=" "
		fi
		set_chipset "${item}"
		echo -ne "${option_counter}.${spaceiface}${item} "
		if [ -z "${chipset}" ]; then
			language_strings "${language}" 245 "blue"
		else
			if [ "${is_rtl_language}" -eq 1 ]; then
				echo -e "${blue_color}// ${normal_color}${chipset} ${yellow_color}:Chipset${normal_color}"
			else
				echo -e "${blue_color}// ${yellow_color}Chipset:${normal_color} ${chipset}"
			fi
		fi
	done

	if [ ${option_counter} -eq 0 ]; then
		if [ -n "${enterprise_mode}" ]; then
			return_to_enterprise_main_menu=1
		elif [[ -z "${enterprise_mode}" ]] && [[ -n "${et_mode}" ]]; then
			return_to_et_main_menu=1
			return_to_et_main_menu_from_beef=1
		fi

		echo
		if [ "${1}" = "dos_pursuit_mode" ]; then
			language_strings "${language}" 510 "red"
		elif [ "${1}" = "internet" ]; then
			language_strings "${language}" 280 "red"
		fi
		language_strings "${language}" 115 "read"
		return 1
	fi

	if [ ${option_counter: -1} -eq 9 ]; then
		spaceiface+=" "
	fi
	print_hint ${current_menu}

	read -rp "> " secondary_iface
	if [ "${secondary_iface}" -eq 0 ] 2> /dev/null; then
		if [ -n "${enterprise_mode}" ]; then
			return_to_enterprise_main_menu=1
		elif [[ -z "${enterprise_mode}" ]] && [[ -n "${et_mode}" ]]; then
			return_to_et_main_menu=1
			return_to_et_main_menu_from_beef=1
		fi
		return 1
	elif [[ ! ${secondary_iface} =~ ^[[:digit:]]+$ ]] || (( secondary_iface < 1 || secondary_iface > option_counter )); then
		if [ "${1}" = "dos_pursuit_mode" ]; then
			invalid_secondary_iface_selected "dos_pursuit_mode"
		else
			invalid_secondary_iface_selected "internet"
		fi
	else
		option_counter2=0
		for item2 in "${secondary_ifaces[@]}"; do
			option_counter2=$((option_counter2 + 1))
			if [[ "${secondary_iface}" = "${option_counter2}" ]]; then
				if [ "${1}" = "dos_pursuit_mode" ]; then
					secondary_wifi_interface=${item2}
					secondary_phy_interface=$(physical_interface_finder "${secondary_wifi_interface}")
					check_interface_supported_bands "${secondary_phy_interface}" "secondary_wifi_interface"
				elif [ "${1}" = "internet" ]; then
					internet_interface=${item2}
				fi
				break
			fi
		done
		return 0
	fi
}

function multint_override_check_vif_support() {

	debug_print
	if [ "${current_menu}" = "evil_twin_attacks_menu" ]; then
		return 0
	else
		if iw "${phy_interface}" info | grep "Supported interface modes" -A 8 | grep "AP/VLAN" > /dev/null 2>&1; then
			return 0
		else
			return 1
		fi
	fi
}

function initialize_multint_language_strings() {

	debug_print

	arr["ENGLISH","multint_text_1"]="Select an interface for AP (Master Mode):"
	arr["SPANISH","multint_text_1"]="Seleccione una interfaz para AP (Master Mode):"
	arr["FRENCH","multint_text_1"]="Sélectionnez une interface pour AP (Master Mode) :"
	arr["CATALAN","multint_text_1"]="Seleccioneu una interfície per a AP (Master Mode):"
	arr["PORTUGUESE","multint_text_1"]="Selecione uma interface para AP (Master Mode):"
	arr["RUSSIAN","multint_text_1"]="Выберите интерфейс для AP (Master Mode):"
	arr["GREEK","multint_text_1"]="Επιλέξτε μια διεπαφή για AP (Master Mode):"
	arr["ITALIAN","multint_text_1"]="Seleziona un'interfaccia per AP (Master Mode):"
	arr["POLISH","multint_text_1"]="Wybierz interfejs dla AP (Master Mode):"
	arr["GERMAN","multint_text_1"]="Wählen Sie eine Schnittstelle für AP (Master Mode):"
	arr["TURKISH","multint_text_1"]="AP (Master Mode) için bir arayüz seçin:"
	arr["ARABIC","multint_text_1"]="حدد واجهة لـ AP (Master Mode):"
	arr["CHINESE","multint_text_1"]="请选择一个接口用于 AP (Master Mode):"

	arr["ENGLISH","multint_text_2"]="Select an interface for Deauth (Monitor Mode):"
	arr["SPANISH","multint_text_2"]="Seleccione una interfaz para Deauth (Monitor Mode):"
	arr["FRENCH","multint_text_2"]="Sélectionnez une interface pour Deauth (Monitor Mode) :"
	arr["CATALAN","multint_text_2"]="Seleccioneu una interfície per a Deauth (Monitor Mode:"
	arr["PORTUGUESE","multint_text_2"]="Selecione uma interface para Deauth (Monitor Mode):"
	arr["RUSSIAN","multint_text_2"]="Выберите интерфейс для and Deauth (Monitor Mode):"
	arr["GREEK","multint_text_2"]="Επιλέξτε μια διεπαφή για Deauth (Monitor Mode):"
	arr["ITALIAN","multint_text_2"]="Seleziona un'interfaccia per Deauth (Monitor Mode):"
	arr["POLISH","multint_text_2"]="Wybierz interfejs dla Deauth (Monitor Mode):"
	arr["GERMAN","multint_text_2"]="Wählen Sie eine Schnittstelle für Deauth (Monitor Mode):"
	arr["TURKISH","multint_text_2"]="Deauth (Monitor Mode) için bir arayüz seçin:"
	arr["ARABIC","multint_text_2"]="حدد واجهة لـ Deauth (Monitor Mode):"
	arr["CHINESE","multint_text_2"]="请选择一个接口用于 Deauth (Monitor Mode):"
}

initialize_multint_language_strings
