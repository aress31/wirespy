<p align="center">
  <img alt="logo" src="https://raw.githubusercontent.com/AresS31/wirespy/dev/images/logo2.jpg" height="200">
  <p align="center">
      <a href="https://www.gnu.org/software/bash/"><img alt="language" src="https://img.shields.io/badge/Lang-Bash%204.2+-blue.svg"></a>
      <a href="https://opensource.org/licenses/Apache-2.0"><img alt="license" src="https://img.shields.io/badge/License-Apache%202.0-red.svg"></a>
      <img alt="version" src="https://img.shields.io/badge/Version-0.6-green.svg">
  </p>
</p>

## WireSpy enables the automation of various WiFi attacks to conduct Man-In-The-Middle-Attacks (MITMAs).

**WireSpy** allows attackers to set up quick honeypots to carry out **MITMAs**. Monitoring and logging functionality is implemented in order to keep records of the victims' traffic/activities. Other tools can be used together with Wirespy to conduct more advanced attacks.

Two type of attacks are supported at the moment:

- **Evil twin**: Force victims to auto-connect to the honeypot by spoofing a _"trusted"_ hotspot (clone an existing access point and de-authenticate its users to force them to transparently connect to the spoofed honeypot).
- **Honeypot**: Set up a simple rogue hotspot and wait for clients to connect.

## Features

- Capture victims' traffic.
- MAC address spoofing.
- Set-up honeypot and evil twin attacks.
- Show the list of in range access points.
- Wireless adapter|card|dongle power amplification.

## Usage

1. Set the script as `executable`:

   ```bash
   chmod +x wirespy.sh
   ```

2. Execute as `root`:

   ```bash
   sudo ./wirespy.sh
   ```

3. Type `help` to get started.

   ```bash
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
   ```

## Roadmap

- [ ] Add WPA/WPA2 support for honeypot.
- [ ] Bash autocompletion.
- [x] Optimise the source code.
- [x] Improve the stability.
- [x] Improve the UI (e.g. uniformise the style and colors).
- [x] Show the status of processes running in the background.
- [ ] Validate all user inputs against regexes.

## Project Information

This script was developed in the context of my [master thesis work](https://www.slideshare.net/AlexandreTeyar/security-in-mobile-banking-apps-154409860) in June 2015.

The project was presented on Pentester Academy TV's toolbox in 2017:

[![Pentester Academy TV's toolbox](https://img.youtube.com/vi/ALSChHZdf5o/0.jpg)](https://www.youtube.com/watch?v=ALSChHZdf5o)

Work on a new improved version has commenced in 2018.

## Sponsor 💖

If you want to support this project and appreciate the time invested in developping, maintening and extending it; consider donating toward my next cup of coffee. ☕

It is easy, all you got to do is press the `Sponsor` button at the top of this page or alternatively [click this link](https://github.com/sponsors/aress31). 💸

## Reporting Issues

Found a bug? I would love to squash it! 🐛

Please report all issues on the GitHub [issues tracker](https://github.com/aress31/wirespy/issues).

## Contributing

You would like to contribute to better this project? 🤩

Please submit all `PRs` on the GitHub [pull requests tracker](https://github.com/aress31/wirespy/pulls).

## License

See [LICENSE](LICENSE).
