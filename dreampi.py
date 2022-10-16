#!/usr/bin/env python3

import argparse
import serial
import serial.tools.list_ports
import os
import logging
import logging.handlers
import sys
import time
import subprocess
import signal
import psutil
from datetime import datetime, timedelta

logger = logging.getLogger('notdreamnorpi')

print('notdreamnorpi\n'
      'https://github.com/samicrusader/notdreamnorpi\n'
      'Fork of Kazade\'s original DreamPi:\n',
      'https://github.com/Kazade/dreampi\n'
      '--\n')


def find_next_unused_ip(start, end: int = 1):
    logger.debug('Finding active network interface...')
    interface = None
    with open('/proc/net/route') as f:
        for line in f.readlines():
            iface, dest, _, flags, _, _, _, _, _, _, _, = line.strip().split()
            if dest != '00000000' or not int(flags, 16) & 2:
                continue
            logger.info(f'Network interface found: {iface}')
            interface = iface

    if not interface:
        raise Exception('No active network interfaces were found')

    parts = [int(x) for x in start.split(".")]
    current_check = parts[-1] - 1

    logger.debug('Finding an unused IP address...')
    output = subprocess.check_output(['arp', '-a', '-i', interface]).decode()

    addresses = tuple()

    for i in range(end):
        while True:
            test_ip = '.'.join([str(x) for x in parts[:3] + [current_check]])
            current_check -= 1
            if test_ip not in addresses and (f'({test_ip})' not in output or f'({test_ip}) at <incomplete>' in output):
                logger.debug(f'Returning IP address: {test_ip}')
                addresses += (test_ip,)
                break

    if not len(addresses) == 0:
        if len(addresses) == 1:
            return addresses[0]
        else:
            return addresses
    else:
        raise Exception('Unable to find a free IP on the network')


def autoconfigure_ppp(device, speed, pap_auth: bool, pppd_debug: bool):
    """
       Every network is different, this function runs on boot and tries
       to autoconfigure PPP as best it can by detecting the subnet and gateway
       we're running on.

       Returns the IP allocated to the client.
    """

    gateway_ip = subprocess.check_output('route -n | grep \'UG[ \t]\' | awk \'{print $2}\'', shell=True).decode()
    subnet = gateway_ip.split('.')[:3]

    host_ip, client_ip = find_next_unused_ip('.'.join(subnet) + '.100', 2)
    logger.info(f'Using host IP address: {host_ip}')
    logger.info(f'Using client IP address: {client_ip}')

    # Using quad9.net for DNS. This will be a user changeable option in the future.
    cmdline = f'/usr/sbin/pppd /dev/{device} {speed} {host_ip}:{client_ip} nodetach ms-dns 9.9.9.9 proxyarp ktune noccp'

    if pppd_debug:
        cmdline += ' logfile /dev/stderr debug'

    if not pap_auth:
        cmdline += ' noauth'
    else:
        cmdline += ' auth require-pap'

    return cmdline, client_ip


def detect_device_and_speed():
    logging.info('Detecting available modems...')
    ports = serial.tools.list_ports.comports()
    for port, _, _ in sorted(ports):
        for speed in [57600, 38400, 19200, 9600, 4800, 2400]:
            logging.debug(f'Trying device {port} at {speed}...')
            m = Modem(port, speed, False)
            m.connect()
            m._serial.write(b'AT\r\n')
            time.sleep(1)
            if m._serial.readline().strip() == b'AT':
                logging.info(f'Using {port} at speed {speed}\n\n\n\n')
                m.disconnect()
                return port, speed
            m.disconnect()
    raise Exception('No usable modem was found. Is it attached?')


class Modem(object):
    def __init__(self, device, speed, disable_dial_tone=True):
        self._device, self._speed = device, speed
        self._serial = None
        self._sending_tone = False

        if not disable_dial_tone:
            self._dial_tone_wav = self._read_dial_tone()
        else:
            self._dial_tone_wav = None

        self._time_since_last_dial_tone = None
        self._dial_tone_counter = 0

    @property
    def device_speed(self):
        return self._speed

    @property
    def device_name(self):
        return self._device

    @staticmethod
    def _read_dial_tone():
        this_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        dial_tone_wav = os.path.join(this_dir, 'dial-tone.wav')

        with open(dial_tone_wav, 'rb') as f:
            dial_tone = f.read()  # Read the entire wav file
            dial_tone = dial_tone[44:]  # Strip the header (44 bytes)

        return dial_tone

    def connect(self):
        if self._serial:
            self.disconnect()

        logger.info(f'Opening serial interface to {self._device}')
        self._serial = serial.Serial(self._device, self._speed, timeout=0)

    def disconnect(self):
        if self._serial and self._serial.isOpen():
            self._serial.close()
            self._serial = None
            logger.info('Serial interface terminated')

    def reset(self):
        self.send_command('ATZ0')  # Send reset command
        self.send_command('ATE0')  # Don't echo our responses

    def start_dial_tone(self):
        if not self._dial_tone_wav:
            return

        self.reset()
        self.send_command('AT+FCLASS=8')  # Enter voice mode
        self.send_command('AT+VLS=1')  # Go off-hook
        self.send_command('AT+VSM=1,8000')  # 8 bit unsigned PCM
        self.send_command('AT+VTX')  # Voice transmission mode

        self._sending_tone = True

        self._time_since_last_dial_tone = (datetime.now() - timedelta(seconds=100))

        self._dial_tone_counter = 0

    def stop_dial_tone(self):
        if not self._sending_tone:
            return

        self._serial.write(b'\0\x10\x03\r\n')
        self.send_escape()
        self.send_command('ATH0')  # Go on-hook
        self.reset()  # Reset the modem
        self._sending_tone = False

    def send_command(self, command, timeout=60, ignore_responses=None):
        ignore_responses = ignore_responses or []  # Things to completely ignore

        valid_responses = [b'OK', b'ERROR', b'CONNECT', b'VCON']

        for ignore in ignore_responses:
            try:
                valid_responses.remove(ignore.encode())
            except ValueError:
                pass

        final_command = f'{command}\r\n'
        self._serial.write(final_command.encode())
        logger.debug(f'Sending {final_command.strip()} to the modem')

        start = datetime.now()

        line = bytes()
        while True:
            new_data = self._serial.readline().strip()

            if not new_data:
                continue

            line = line + new_data
            for resp in valid_responses:
                if resp == b'CONNECT' and command == 'AT+VTX':
                    logger.info('Modem is listening.')
                if resp in line:
                    logger.debug((line[line.find(resp):]).decode())
                    return  # We are done

            if (datetime.now() - start).total_seconds() > timeout:
                raise IOError('There was a timeout while waiting for a response from the modem')

    def send_escape(self):
        time.sleep(1.0)
        self._serial.write(b'+++')
        time.sleep(1.0)

    def update(self):
        now = datetime.now()
        if self._sending_tone:
            # Keep sending dial tone
            BUFFER_LENGTH = 1000
            TIME_BETWEEN_UPLOADS_MS = (1000.0 / 8000.0) * BUFFER_LENGTH

            milliseconds = (now - self._time_since_last_dial_tone).microseconds * 1000
            if not self._time_since_last_dial_tone or milliseconds >= TIME_BETWEEN_UPLOADS_MS:
                byte = self._dial_tone_wav[self._dial_tone_counter:self._dial_tone_counter + BUFFER_LENGTH]
                self._dial_tone_counter += BUFFER_LENGTH
                if self._dial_tone_counter >= len(self._dial_tone_wav):
                    self._dial_tone_counter = 0
                self._serial.write(byte)
                self._time_since_last_dial_tone = now


class GracefulKiller(object):
    def __init__(self):
        self.kill_now = False
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, _):
        logging.warning(f'Received signal: {signum}')
        self.kill_now = True


def main():
    # Make sure pppd isn't running
    logging.info('Killing pppd if running...')
    for proc in psutil.process_iter():
        try:
            if 'pppd' in proc.name().lower():
                logging.info(f'Killing pppd (pid {proc.pid})...')
                proc.send_signal(9)  # SIGKILL
        except psutil.ZombieProcess:
            logging.error(f'pppd (pid {proc.pid}) is currently in a zombie state. There is likely locking IO'
                          'somewhere. You may need to restart your system.')
            return 1
        except psutil.NoSuchProcess:
            pass
        except (Exception, psutil.AccessDenied) as e:
            logging.error(f'Cannot kill pppd (pid {proc.pid}): {e}')
            return 1

    # Startup checks, make sure that we don't do anything until
    # we have a modem and internet connection
    while True:
        logger.info('Detecting connection and modem...')
        device_and_speed = detect_device_and_speed()

        if device_and_speed:
            logger.info('Modem found!')
            break
        elif not device_and_speed:
            logger.warning('Unable to find a modem device. Waiting...')

        time.sleep(5)

    modem = Modem(device_and_speed[0], device_and_speed[1], args.disable_dial_tone)
    cmdline, client_ip = autoconfigure_ppp(modem.device_name, modem.device_speed, args.enable_pap_auth,
                                           args.enable_pppd_debug)

    mode = 'LISTENING'

    modem.connect()
    if not args.disable_dial_tone:
        modem.start_dial_tone()

    time_digit_heard = datetime.now()

    while True:
        now = datetime.now()

        try:
            if mode == 'LISTENING':
                modem.update()
                char = modem._serial.read(1).strip()
                if not char:
                    continue

                if ord(char) == 16:
                    # DLE character
                    try:
                        char = modem._serial.read(1)
                        digit = int(char)
                        logger.info(f'Heard: {digit}')

                        mode = 'ANSWERING'
                        modem.stop_dial_tone()
                        time_digit_heard = now
                    except (TypeError, ValueError):
                        pass
            elif mode == 'ANSWERING':
                if (now - time_digit_heard).total_seconds() > 8.0:
                    time_digit_heard = None
                    modem.reset()
                    modem.send_command('ATA', ignore_responses=['OK'])
                    time.sleep(5)
                    logger.info('Call was answered.')
                    mode = 'CONNECTED'
            elif mode == 'CONNECTED':
                modem.disconnect()
                pppd = subprocess.Popen(cmdline.split(' '), stderr=sys.stderr)
                try:
                    pppd.wait()
                except KeyboardInterrupt:
                    pppd.send_signal(9)  # SIGKILL
                    time.sleep(1)
                    raise KeyboardInterrupt
                print('return code:', str(pppd.returncode))
                mode = 'LISTENING'
                modem.connect()
                modem.reset()
                if not args.disable_dial_tone:
                    modem.start_dial_tone()
        except KeyboardInterrupt:
            modem.send_escape()
            modem.reset()
            if mode == 'LISTENING':
                print('Your modem is currently awaiting a connection. You will need to replug your modem.')
            exit(0)
    return 0


if __name__ == '__main__':
    # ArgumentParser setup
    parser = argparse.ArgumentParser(
        description='notdreamnorpi: hacky pppd wrapper for the masses',
        prog='python3 dreampi.py'
    )
    parser.add_argument('--disable-dial-tone', '-d', action='store_true', default=False,
                        help='Disable simulated dial tone (default enabled)')
    parser.add_argument('--enable-pap-auth', '-a', action='store_true', default=False,
                        help='Enable PAP auth in pppd (default off)')
    parser.add_argument('--enable-pppd-debug', action='store_true', default=False,
                        help='Enable pppd debug messages (sent to stdout)')
    parser.add_argument('--verbose', '-v', action='count', default=2,
                        help='Increase verbosity (use like -vv, max level is around 3)')

    args = parser.parse_args()
    # logger.setLevel(args.verbose * 10)  # FIXME: Log levels are not right
    logger.setLevel(logging.DEBUG)

    quit(main())
