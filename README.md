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
* **Honeypot**     : set up a simple rogue hotspot and wait for clients to connect
* **Evil-twin**    : force victims to auto-connect to the honeyspot by spoofing a *"trusted"* hotspot

## Features
* Amplificate the wireless adapter/dongle power
* MAC address spoofing
* Set-up rogue access-point aka honeypot
* Further evil-twin attack: 
    1. Clone an access-point
    2. De-authenticate its users to force them to transparently auto-connect  
      to the evil-twin (spoofed) access-point
* Capture the victims' traffic

## Usage
1. Make the script executable:
```console
$ chmod +x wirespy.sh
```
2. Run the script with root privileges:
```console
$ sudo ./wirespy.sh
```

## Possible Improvements
- [ ] Add new features such as:
  - [ ] bash autocompletion
  - [ ] validating all user inputs
  - [ ] adding WPA/WPA2 for honeypot
  - [ ] adding a status/info command showing the processes running in the background
- [ ] Improve the UI
- [ ] Source code optimisation

## Project Information
This script was developed in the context of my master thesis work in June 2015.

The project was presented on Pentester Academy TV's toolbox in 2017:

[![Pentester Academy TV's toolbox](https://img.youtube.com/vi/ALSChHZdf5o/0.jpg)](https://www.youtube.com/watch?v=ALSChHZdf5o)

Work on a new improved version has commenced in 2018.

## Donation
If you want to support my work doing a donation, it will be very much appreciated:
* Bitcoin       : **15aFaQaW9cxa4tRocax349JJ7RKyj7YV1p**
* Bitcoin Cash  : **qqez5ed5wjpwq9znyuhd2hdg86nquqpjcgkm3t8mg3**
* Ether         : **0x70bC178EC44500C17B554E62BC31EA2B6251f64B**

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
