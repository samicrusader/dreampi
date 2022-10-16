# notdreamnorpi

Hacky `pppd` wrapper for the masses.

This is a fork of the [DreamPi](https://github.com/Kazade/dreampi) project, updated to port the script to the modern era.

### Original description

A daemon that creates a bridge between a Dreamcast's Dial-up Modem, and the Internet via the Pi

## Installation

* You need a Linux distribution to use this script. Windows will not work unless someone has a scriptable PPP implementation.
* Preferrably a Conexant RD02-D400 modem. Any modem will work however, as long as it is recognizable by both the Linux kernel that you are running, and wvdial.
* Install Python 3.6+ (including `pip`), `ppp`, and `net-tools` from your system's package manager.
* Install these python packages: `psutil`, `pyserial`, `sh`.
  * Arch Linux users should install `python-psutil`, `python-pyserial`, and `python-sh`
  * Debian users should install `python3-psutil`, `python3-serial`, and `python3-sh`
  * Other distributions should consult their package manager's repositories. pip should only really be used if packages aren't available for your distribution.
* Clone this repository, `cd` into the folder, and run `python3 dreampi.py` as root.
  * You can call the script with `--help` to get a list of options. 
  * If your device has trouble with the dial tone simulation, append `--disable-dial-tone=False` to the command line.
  * If you have PAP authentication setup for pppd (required for old WebTV classic clients in flashrom mode), append `--enable-pap-auth` to the command line if you'd like to use it.
  * If you want more advanced logging from pppd, append `--enable-pppd-debug` to the command line.

## Changes from the original

* Script is ported from Python 2.x to Python 3.6+
* Dreamcast-specific components are stripped away
* Better compatibility with other modems (detected by your system)
* Command line argument parsing is changed from `sys.argv` lookup to `argparse`
* Ability to toggle PAP authentication and logging level
* Faster start with "optimized" code for network detection
* Syslog/`systemd-journal` requirement removed in favor of just calling `pppd` directly