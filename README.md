# notdreamnorpi

This is a fork of DreamPi that ports the script to Python 3, removes unnecessary requirements, and removes Dreamcast-specific integrations for regular person use.

### Original description

A daemon that creates a bridge between a Dreamcast's Dial-up Modem, and the Internet via the Pi

## Installation

* You need a Linux distribution with either systemd, or your syslog output to `/var/log/messages` OR `/var/log/syslog`.
* Preferrably a Conexant RD02-D400 modem. Any modem will work however, as long as it is recognizable by the Linux kernel that you are running.
* If it is not already installed, install pppd.
* Install Python 3.6+ from your package manager.
* Install these packages: `pyserial`, and `sh`.
  * Arch Linux users should install `python-pyserial`, and `python-sh`
  * Debian users should install `python3-serial`, and `python3-sh`
  * Other distributions should consult their package manager's repositories. pip should only really be used if packages aren't available for your distribution.
* Clone this repository, `cd` into the folder, and run `python3 dreampi.py` as root.
  * If your device has trouble with the dial tone, append `--disable-dial-tone` to the command line.
  * If you have PAP authentication setup for pppd, append `--enable-pap-auth` to the command line if you'd like to use it.