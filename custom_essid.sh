#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="Custom ESSID"
plugin_description="Plugin to specify custom ESSID for hidden networks"
plugin_author="xpz3"

#Enabled 1 / Disabled 0 - Set this plugin as enabled - Default value 1
plugin_enabled=1

plugin_minimum_ag_affected_version="11.41"
plugin_maximum_ag_affected_version=""

plugin_distros_supported=("*")

function custom_essid_prehook_set_hostapd_config() {

	debug_print

	if [[ "${essid}" == "(Hidden Network)" ]]; then
		language_strings "${language}" "custom_essid_text_1" "yellow"
		read -p "> " essid
	fi
}

#Prehook for hookable_for_languages function to modify language strings
#shellcheck disable=SC1111
function custom_essid_prehook_hookable_for_languages() {

	arr["ENGLISH","custom_essid_text_1"]="A hidden network has been chosen for Evil Twin attack. Please specify the ESSID of the target AP to continue"
	arr["SPANISH","custom_essid_text_1"]="Se ha seleccionado una red oculta para el ataque Evil Twin. Por favor especifica el ESSID del AP objetivo para continuar"
	arr["FRENCH","custom_essid_text_1"]="\${pending_of_translation} Un réseau caché pour l'attaque twin diabolique a été sélectionné. Veuillez spécifier l'ESSID de l'objectif AP à continuer"
	arr["CATALAN","custom_essid_text_1"]="\${pending_of_translation} S'ha seleccionat una xarxa oculta per a l'atac bessó malvat. Especifiqueu l'ESSID de l'AP Objectiu per continuar"
	arr["PORTUGUESE","custom_essid_text_1"]="\${pending_of_translation} Uma rede oculta para o ataque gêmeo do mal foi selecionada. Especifique o ESSID do objetivo AP para continuar"
	arr["RUSSIAN","custom_essid_text_1"]="\${pending_of_translation} Была выбрана скрытая сеть для злой атаки близнецов. Пожалуйста, укажите ESSID цели AP для продолжения"
	arr["GREEK","custom_essid_text_1"]="\${pending_of_translation} Έχει επιλεγεί ένα κρυφό δίκτυο για την κακή δίδυμη επίθεση. Προσδιορίστε το ESSID του αντικειμενικού AP να συνεχιστεί"
	arr["ITALIAN","custom_essid_text_1"]="\${pending_of_translation} È stata selezionata una rete nascosta per l'attacco gemello malvagio. Si prega di specificare l'ESSID dell'obiettivo AP per continuare"
	arr["POLISH","custom_essid_text_1"]="\${pending_of_translation} Wybrano ukrytą sieć złego ataku bliźniaczego. Podaj ESSID obiektywnego AP, aby kontynuować"
	arr["GERMAN","custom_essid_text_1"]="\${pending_of_translation} Ein verstecktes Netzwerk für den bösen Twin -Angriff wurde ausgewählt. Bitte geben Sie den ESSID des objektiven AP an, um fortzufahren"
	arr["TURKISH","custom_essid_text_1"]="\${pending_of_translation} Kötü ikiz saldırı için gizli bir ağ seçildi. Devam etmek için lütfen nesnel AP'nin ESSIDini belirtin"
	arr["ARABIC","custom_essid_text_1"]="\${pending_of_translation} تم اختيار شبكة خفية للهجوم التوأم الشرير. يرجى تحديد ESSID من الهدف AP للمتابعة"
	arr["CHINESE","custom_essid_text_1"]="\${pending_of_translation} 已经选择了一个邪恶双胞胎攻击的隐藏网络。请指定目标AP的ESSID"
}
