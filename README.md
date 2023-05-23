# airgeddonplugins

<strong>Description</strong>

<ul>
    <li><strong>avoid_airmon.sh:</strong> This plugin disables airmon-ng to be used to start and stop monitor mode on an interface. <code>iw</code>will be used instead.</li>
    <li><strong>multint.sh:</strong> This plugin enables Airgeddon to use more than one interface to be used with Captive Portal attack. By default, Airgeddon uses <code>Virtual Interface</code> method on supported chipsets to create  monitor mode and master mode required to run captive portal attack. For users who do not have a fully compatible chipset, they can use this plugin to use multiple cards that support monitor and master mode one per card to run captive portal attack.</li>
    <li><strong>nogui.sh:</strong> This plugin voids the requirement of xterm or tmux for evil twin attack. This plugin only works with Evil Twin attack with Captive Portal method (Option 9 in Evil Twin attacks menu)</li>
    <li><strong>custom_essid.sh:</strong> This plugin allows you to specify custom name for a target AP with hidden SSID, after discovering it with deauth attack.</li>
    <li><strong>mass_handshake_capture.sh:</strong> This plugin allows you to mass capture Handshake/PMKID from nearby WPA networks. After downloading the plugin to the airgeddon/plugins directory, run airgeddon, select interface and put the card into monitor mode and then goto Handshake/PMKID Tools menu and choose Option 8. Mass Handshake/PMKID Capture and then follow the instructions. There are some variables that can be set according to the needs. Open the plugin file and see the top section. <i>In the new update this plugin allows you to save the AP details(essid, bssid, channel, encryption and handshake/PMKID file location) whose handshake has been captured. You can use this file to automatically start Evil Twin captive portal attack using airgeddon_cli.sh plugin which takes the file as an argument and starts the evil twin attack.</i></li>
</ul>

<strong>Usage</strong>
<br>
Just download and copy the plugin file to the plugins folder inside airgeddon directory. Please do not rename any plugin file. After copying the file, just run airgeddon as you normally would and the plugin will do its job.
