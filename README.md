<p align="center">
  <img alt="logo" src="https://raw.githubusercontent.com/AresS31/wirespy/dev/images/logo2.jpg" height="200">
  <p align="center">
      <a href="https://www.gnu.org/software/bash/"><img alt="language" src="https://img.shields.io/badge/Lang-Bash%204.2+-blue.svg"></a>
      <a href="https://opensource.org/licenses/Apache-2.0"><img alt="license" src="https://img.shields.io/badge/License-Apache%202.0-red.svg"></a>
      <img alt="version" src="https://img.shields.io/badge/Version-0.5-green.svg">
      <img alt="bitcoin" src="https://img.shields.io/badge/Bitcoin-15aFaQaW9cxa4tRocax349JJ7RKyj7YV1p-yellow.svg">
      <img alt="bitcoin cash" src="https://img.shields.io/badge/Bitcoin%20Cash-qqez5ed5wjpwq9znyuhd2hdg86nquqpjcgkm3t8mg3-yellow.svg">
      <img alt="ether" src="https://img.shields.io/badge/Ether-0x70bC178EC44500C17B554E62BC31EA2B6251f64B-yellow.svg">
  </p>
</p>

## WireSpy enables the automation of various WiFi attacks to conduct Man-In-The-Middle-Attacks (MITMAs).
**WireSpy** allows attackers to set up quick honeypots to carry out **MITMAs**. Monitoring and logging functionality is implemented in order to keep records of the victims' traffic/activities. Other tools can be used together with Wirespy to conduct more advanced attacks. 

Two type of attacks are supported at the moment:
* **Honeypot**: Set up a simple rogue hotspot and wait for clients to connect.
* **Evil twin**: Force victims to auto-connect to the honeypot by spoofing a *"trusted"* hotspot (clone an existing access point and de-authenticate its users to force them to transparently connect to the spoofed honeypot).

## Features
* Capture victims' traffic
* MAC address spoofing
* Set-up honeypot and evil twin attacks
* Show the list of in range access point and their details 
* Wireless adapter|card|dongle power amplification

## Usage
1. Make the script executable:
```console
$ chmod +x wirespy.sh
```
2. Run the script with root privileges:
```console
$ sudo ./wirespy.sh
```
3. Type `help` to display the list of available commands.

## Available commands
```shell
Attacks:
    eviltwin      > launch an evil-twin attack
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
```

## Possible Improvements
- [x] Add a command to show the status of the running commands in the background
- [ ] Add WPA/WPA2 support for honeypot
- [ ] Bash autocompletion
- [x] Improve the stability
- [x] Improve the UI (e.g. uniformise the style)
- [x] Source code optimisation
- [ ] Validate all user inputs against regexes

## Project Information
This script was developed in the context of my master thesis work in June 2015.

The project was presented on Pentester Academy TV's toolbox in 2017:

[![Pentester Academy TV's toolbox](https://img.youtube.com/vi/ALSChHZdf5o/0.jpg)](https://www.youtube.com/watch?v=ALSChHZdf5o)

Work on a new improved version has commenced in 2018.

## One-time donation
* Donate via Bitcoin      : **15aFaQaW9cxa4tRocax349JJ7RKyj7YV1p**
* Donate via Bitcoin Cash : **qqez5ed5wjpwq9znyuhd2hdg86nquqpjcgkm3t8mg3**
* Donate via Ether        : **0x70bC178EC44500C17B554E62BC31EA2B6251f64B**

## License
   Copyright (C) 2015 - 2018 Alexandre Teyar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
   limitations under the License.
