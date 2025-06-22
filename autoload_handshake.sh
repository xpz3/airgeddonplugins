#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

###### GENERIC PLUGIN VARS ######

plugin_name="autoload_handshake"
plugin_description="If an existing handshake is found in the default location while performing Evil Twin, Airgeddon automatically loads it"
plugin_author="xpz3"

#Enabled 1 / Disabled 0 - Set this plugin as enabled - Default value 1
plugin_enabled=1

###### PLUGIN REQUIREMENTS ######

#Set airgeddon versions to apply this plugin (leave blank to set no limits, minimum version recommended is 10.0 on which plugins feature was added)
plugin_minimum_ag_affected_version="11.50"
plugin_maximum_ag_affected_version=""

#Set only one element in the array "*" to affect all distros, otherwise add them one by one with the name which airgeddon uses for that distro (examples "BlackArch", "Parrot", "Kali")
plugin_distros_supported=("*")

#Default handshake file location
ah_default_handshake_location="/root/"

function autoload_handshake_override_ask_et_handshake_file() {

	debug_print

	echo
	readpath=0
	local ah_handshake_file

	if [[ -z "${enteredpath}" ]] && [[ -z "${et_handshake}" ]]; then
		ah_handshake_file="${ah_default_handshake_location}handshake-${bssid}.cap"
		if [ -f "${ah_handshake_file}" ]; then
			ask_yesno "autoload_handshake_text_1" "yes"
			if [ "${yesno}" = "y" ]; then
				et_handshake="${ah_handshake_file}"
			else
				readpath=1
			fi
		else
			readpath=1
		fi
	elif [[ -z "${enteredpath}" ]] && [[ -n "${et_handshake}" ]]; then
		language_strings "${language}" 313 "blue"
		ask_yesno 187 "yes"
		if [ "${yesno}" = "n" ]; then
			readpath=1
		fi
	elif [[ -n "${enteredpath}" ]] && [[ -z "${et_handshake}" ]]; then
		language_strings "${language}" 151 "blue"
		ask_yesno 187 "yes"
		if [ "${yesno}" = "y" ]; then
			et_handshake="${enteredpath}"
		else
			readpath=1
		fi
	elif [[ -n "${enteredpath}" ]] && [[ -n "${et_handshake}" ]]; then
		language_strings "${language}" 313 "blue"
		ask_yesno 187 "yes"
		if [ "${yesno}" = "n" ]; then
			readpath=1
		fi
	fi

	if [ ${readpath} -eq 1 ]; then
		validpath=1
		while [[ "${validpath}" != "0" ]]; do
			read_path "ethandshake"
		done
	fi
}

#Prehook for hookable_for_languages function to modify language strings
function autoload_handshake_prehook_hookable_for_languages() {

	arr["ENGLISH","autoload_handshake_text_1"]="An already captured handshake file was found in \${ah_default_handshake_location}. Do you want to use that file? \${normal_color}\${visual_choice}"
	arr["SPANISH","autoload_handshake_text_1"]="Se encontró un archivo de handshake ya capturado en \${ah_default_handshake_location}. ¿Quieres usar ese archivo? \${normal_color}\${visual_choice}"
	arr["FRENCH","autoload_handshake_text_1"]="Un fichier de handshake déjà capturé a été trouvé dans \${ah_default_handshake_location}. Voulez-vous utiliser ce fichier ? \${normal_color}\${visual_choice}"
	arr["CATALAN","autoload_handshake_text_1"]="S'ha trobat un fitxer de handshake ja capturat a \${ah_default_handshake_location}. Vols utilitzar aquest fitxer? \${normal_color}\${visual_choice}"
	arr["PORTUGUESE","autoload_handshake_text_1"]="Um arquivo de handshake já capturado foi encontrado em \${ah_default_handshake_location}. Deseja usar esse arquivo? \${normal_color}\${visual_choice}"
	arr["RUSSIAN","autoload_handshake_text_1"]="В \${ah_default_handshake_location} найден ранее захваченный файл handshake. Вы хотите использовать этот файл? \${normal_color}\${visual_choice}"
	arr["GREEK","autoload_handshake_text_1"]="Ένα ήδη καταγεγραμμένο αρχείο handshake βρέθηκε στο \${ah_default_handshake_location}. Θέλετε να χρησιμοποιήσετε αυτό το αρχείο; \${normal_color}\${visual_choice}"
	arr["ITALIAN","autoload_handshake_text_1"]="È stato trovato un file di handshake già acquisito in \${ah_default_handshake_location}. Vuoi usare quel file? \${normal_color}\${visual_choice}"
	arr["POLISH","autoload_handshake_text_1"]="W \${ah_default_handshake_location} znaleziono wcześniej przechwycony plik handshake. Czy chcesz użyć tego pliku? \${normal_color}\${visual_choice}"
	arr["GERMAN","autoload_handshake_text_1"]="Eine bereits erfasste Handshake-Datei wurde in \${ah_default_handshake_location} gefunden. Möchten Sie diese Datei verwenden? \${normal_color}\${visual_choice}"
	arr["TURKISH","autoload_handshake_text_1"]="\${ah_default_handshake_location} konumunda önceden yakalanmış bir handshake dosyası bulundu. Bu dosyayı kullanmak istiyor musunuz? \${normal_color}\${visual_choice}"
	arr["ARABIC","autoload_handshake_text_1"]="تم العثور على ملف handshake تم التقاطه بالفعل في \${ah_default_handshake_location}. هل تريد استخدام هذا الملف؟ \${normal_color}\${visual_choice}"
	arr["CHINESE","autoload_handshake_text_1"]="在 \${ah_default_handshake_location} 中找到一个已捕获的握手文件。您想使用该文件吗？ \${normal_color}\${visual_choice}"
}
