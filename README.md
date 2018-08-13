<p align="center">
  <img alt="logo" src="https://raw.githubusercontent.com/AresS31/wirespy/dev/images/logo.png" height="200" />
  <p align="center">
  	<a href="https://www.gnu.org/software/bash/"><img alt="language" src="https://img.shields.io/badge/Lang-Bash%204.2+-blue.svg"></a>
  	<a href="https://opensource.org/licenses/Apache-2.0"><img alt="license" src="https://img.shields.io/badge/License-apache%202.0-red.svg"></a>
  	<a><img alt="version" src="https://img.shields.io/badge/Version-0.5-green.svg"></a>
  </p>
</p>

## **WireSpy** enables the automation of various WiFi attacks to conduct Man-In-The-Middle-Attacks (MITMAs).

WireSpy allows attackers to set up quick honeypots to carry out **MITMAs**. Monitoring and logging functionality is implemented in order to keep records of the victims' traffic/activities. Other tools can be used together with Wirespy to conduct more advanced attacks. 

Two type of attacks are supported at the moment:
* **Honeypot:** set up a simple rogue hotspot and wait for clients to connect
* **Evil-twin:** force victims to auto-connect to the honeyspot by spoofing a *"trusted"* hotspot

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
- [ ] Add new features
- [ ] Improve the UI
- [ ] Source code optimisation

## Project Information
This script was developed in the context of my master thesis work in June 2015.

The project was presented on [Pentester Academy TV's toolbox](https://www.youtube.com/watch?v=ALSChHZdf5o) in 2017Pentester Academy TV's toolbox in 2017.

Work on a new improved version has commenced in 2018.

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
