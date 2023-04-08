#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="Skip Loginctl"
plugin_description="Skip loginctl in nethunter"
plugin_author="xpz3"

plugin_enabled=1

plugin_minimum_ag_affected_version="10.0"
plugin_maximum_ag_affected_version=""

plugin_distros_supported=("*")

function skip_loginctl_posthook_graphics_prerequisites() {

	debug_print

	graphics_system="${XDG_SESSION_TYPE}"
}
