# airgeddonplugins
<strong>Disclaimer: I won't be responsible for anything you use with these plugins. Please use them for educational purposes only</strong>

<strong>Description</strong>

<ul>
    <li>
        <strong>avoid_airmon.sh:</strong> This plugin disables airmon-ng to be used to start and stop monitor mode on an interface. <code>iw</code>will be used instead.
    </li>
    <li>
        <strong>multint.sh:</strong> This plugin enables Airgeddon to use more than one interface to be used with Captive Portal attack. By default, Airgeddon uses <code>Virtual Interface</code> method on supported chipsets to create  monitor mode and master mode required to run captive portal attack. For users who do not have a fully compatible chipset, they can use this plugin to use multiple cards that support monitor and master mode one per card to run captive portal attack.
    </li>
    <li>
        <strong>nogui.sh:</strong> This plugin voids the requirement of xterm or tmux for evil twin attack. This plugin only works with Evil Twin attack with Captive Portal method (Option 9 in Evil Twin attacks menu)
    </li>
    <li>
        <strong>mass_handshake_capture.sh:</strong> This plugin allows you to mass capture Handshake/PMKID from nearby WPA networks. After downloading the plugin to the airgeddon/plugins directory, run airgeddon, select interface and put the card into monitor mode and then goto <code>Handshake/PMKID/Decloaking tools menu</code> and choose Option <code>10. Mass Handshake/PMKID Capture</code> and then follow the instructions. There are some variables that can be set according to the needs. Open the plugin file and see the top section. The minimum required airgeddon version is now 11.50. <i>In the new update this plugin allows you to save the AP details(essid, bssid, channel, encryption and handshake/PMKID file location) whose handshake has been captured. You can use this file to automatically start Evil Twin captive portal attack using airgeddon_cli.sh plugin which takes the file as an argument and starts the evil twin attack.</i>
    </li>
    <li>
        <strong>airgeddon_cli.sh</strong> This plugin enables command line interface for airgeddon evil twin with captive portal attack. It can work in two ways, one is to specify just the vif capable interface and a file containing essid, bssid, channel, encryption type and handshake/PMKID file location. The plugin will then start the evil twin attack using the provided values in the file. All other options will be set to default and can be edited from the plugin. The second method to use the plugin is to specify the bssid, essid, channel, encryption type, handshake/PMKID file path, vif capable interface and any other desired values as command line arguments. The detailed usage info can be found by downloading the plugin and then running <code>bash airgeddon.sh -u</code> If no command line arguments are passed, airgeddon will start normally.
    </li>
    <li>
        <strong>autoload_handshake.sh</strong> This plugin automatically loads a previously captured handshake file for a selected target, if the user wishes to. You can change the default handshake location by editing the variable in the file.
    </li>
    <li>
        <strong>customportals.sh</strong> This plugin makes it easy to create or edit custom portals for use with airgeddon. It has all the portals from Fluxion included and most if not all bugs were fixed. The plugin ensures compatibility with airgeddon. If you just want to use these portals, you don’t need to make any changes. Simply download the plugin file along with the `customportals/` directory into the airgeddon plugins folder. Then run airgeddon as usual, and towards the end it will ask whether you want to use a custom portal or not. If you answer yes, it will list all the available custom portals in the <code>plugins/customportals/</code> directory. It will display all the individual portal folders inside it. When you want to create a new portal, create or download the necessary files, place them in a directory and copy that directory into the <code>plugins/customportals/</code> folder along with the others. There are a few things to keep in mind when developing a custom portal. Only use <code>.html</code> files avoiding use of <code>.htm</code> files, as they will not work. Your portal must include a <code>&lt;form&gt;</code> tag with a password field named <code>"password|password1|passphrase|key|key1|wpa|wpa_psw"</code>. The <code>&lt;form&gt;</code> tag must post to <code>check.htm</code> with the password field and its value. If you want to use PHP in your custom portal, you must install php-cgi, Apache, or any other handler, and uncomment the line containing the variable <code>customportals_php_handle=0</code> in <code>customportals.sh</code>. That will enable the use of PHP files as real PHP and make them compatible with airgeddon. <strong>If you have any questions, please ask in the airgeddon Discord server <code>#plugins-development</code> channel rather than opening a bug report here. The minimum required airgeddon version is now 11.60.</strong>
    </li>
    <li>
        <strong>airgeddon_cli_multint.sh</strong> This plugin enables multiple interface and command line support for airgeddon evil twin with captive portal attack. This plugin can work as the old <code>multint.sh</code> plugin or <code>airgeddon_cli.sh</code> plugin or <code>airgeddon_cli_multint.sh</code> plugin, depending on the CLI arguments passed. If you run <code>bash airgeddon.sh</code> the CLI will be disabled and you will be prompted to choose the multiple interfaces. If you specify <code>--ap-interface <wlanX></code> and <code>--deauth-interface <wlanX></code> as CLI arguments, then the combined multint and CLI version will be activated. If you pass in only one VIF capable interface, then multint will be disabled.<br>
            <strong>1. Example CLI and Multint with File Mode</strong><code>bash airgeddon.sh --ap-interface wlan0 --deauth-interface wlan1 -f TargetAP.txt</code> Here both AP and Deauth interfaces are passed as CLI arguments and a filename with minimum required values to start the attack is specified too. The file contains <code>essid|bssid|channel|encryption|handshake_file_path.cap</code>.<br>
            <strong>2. Example Full CLI with Multint mode(No file, all arguments are typed)</strong> <code>bash airgeddon.sh --ap-interface wlan0 --deauth-interface wlan1 --essid "TargetAP" --bssid "AA:BB:CC:DD:EE:FF" --channel 6 --enc "WPA2" --hsfile "/root/handshake-AA:BB:CC:DD:EE:FF.cap"</code>. <strong>Note - When using this mode, make sure to not use the <code>-i wlanX</code> CLI argument as it is for the third mode which utilizes single VIF capable interface to run the attach through CLI mode.</strong> <br>
            <strong>3. Examples CLI No multint mode(the interface wlan0 must be VIF capable)</strong><br>
                <code>bash airgeddon.sh -i wlan0 -f TargetAP.txt</code><br><code>bash airgeddon.sh -i wlan0 --essid "TargetAP" --bssid "AA:BB:CC:DD:EE:FF" --channel 6 --enc "WPA2" --hsfile "/root/handshake-AA:BB:CC:DD:EE:FF.cap"</code><br>
            <strong>4. Example No CLI only interactive multint mode</strong><br>
                <code>bash airgeddon.sh</code><br>
            <strong>The detailed usage info can be found by downloading the plugin and then running</strong> <code>bash airgeddon.sh -u</code>
    </li>
</ul>

<strong>Usage</strong>
<br>
Just download and copy the plugin file to the plugins folder inside airgeddon directory. Please do not rename any plugin file. After copying the file, just run airgeddon as you normally would and the plugin will do its job.
