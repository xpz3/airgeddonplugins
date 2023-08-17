#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="Custom ESSID"
plugin_description="Plugin to specify custom ESSID for hidden networks"
plugin_author="xpz3"

#Enabled 1 / Disabled 0 - Set this plugin as enabled - Default value 1
plugin_enabled=1

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""

plugin_distros_supported=("*")

function custom_essid_prehook_set_hostapd_config() {

	debug_print

	if [[ "${essid}" == "(Hidden Network)" ]]; then
		language_strings "${language}" "custom_essid_text_1" "yellow"
		read -p "> " essid
	fi
}

function initialize_custom_essid_language_strings() {

	debug_print
	
	arr["ENGLISH","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["SPANISH","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["FRENCH","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["CATALAN","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["PORTUGUESE","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["RUSSIAN","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["GREEK","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["ITALIAN","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["POLISH","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["GERMAN","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["TURKISH","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["ARABIC","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the SSID of the target AP to continue"
	arr["CHINESE","custom_essid_text_1"]="您选择了一个隐藏的网络发起邪恶双胞胎攻击，请手动指定目标隐藏AP的SSID以继续"
}

initialize_custom_essid_language_strings

