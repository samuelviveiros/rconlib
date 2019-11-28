#!/usr/bin/env python3

__author__ = 'Samuel Viveiros Gomes a.k.a Dartz8901'
__license__ = './LICENSE'  # MIT License
__date__ = 'November 28, 2019'
__version__ = '0.1.0'
__credits__ = 'I tooked a couple ideas from SRCDS.py by Chistopher Munn.'

import os
import sys
import socket
import struct
from random import randrange
from optparse import OptionParser

# On sending packets.
SERVERDATA_AUTH = 3
SERVERDATA_EXECCOMMAND = 2

# On receiving packets.
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_RESPONSE_VALUE = 0

DEFAULT_TIMEOUT = 60.0
MAX_PACKET_ID = 2 ** 32 - 1
DEFAULT_SIZE = 10
AUTH_PACKET_ID = 1001
EMPTY_RESPONSE = {
    'packet_size': DEFAULT_SIZE,
    'packet_id': 0,
    'packet_type': SERVERDATA_RESPONSE_VALUE,
    'packet_body': '',
    'empty_string': ''
}

NOT_IMPLEMENTED = "This hasn't been implemented yet."


class RCONError(Exception):
    pass


class RCONAuthError(RCONError):
    pass


class RCONSocketError(RCONError):
    pass


class RCONTimeoutError(RCONError):
    pass


class RCONPacket:
    def __init__(self):
        raise NotImplementedError(NOT_IMPLEMENTED)


class RCON:
    def __init__(self, ip, port=27015, timeout=DEFAULT_TIMEOUT):
        self.ip = ip
        self.port = port
        self._timeout = timeout
        self.sockt = None
        self._is_debug_active = False
        self.sockt = None

    def connect(self):
        if isinstance(self.sockt, socket.socket):
            self.disconnect()

        self.sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sockt.settimeout(self.timeout)
        srcds = (self.ip, self.port)
        self.sockt.connect(srcds)

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, new_value):
        self._timeout = new_value
        self.sockt.settimeout(self._timeout)

    def disconnect(self):
        if isinstance(self.sockt, socket.socket):
            self.sockt.close()
        self.sockt = None

    def send(self, packet_id, packet_type, packet_body):
        if not isinstance(self.sockt, socket.socket):
            raise RCONSocketError('There is no connection established.')

        null_terminator = b'\x00'
        empty_string = b'' + null_terminator
        packet_id = struct.pack('<I', packet_id)
        packet_type = struct.pack('<I', packet_type)
        packet_body = bytes(packet_body, 'ascii') + null_terminator
        packet = packet_id + packet_type + packet_body + empty_string
        packet_size = struct.pack('<I', len(packet))
        packet = packet_size + packet

        if self._is_debug_active:
            dump = ' '.join(format(b, '02x') for b in packet)
            print('[DEBUG] RCON.send (packet mounted): {}'.format(dump))

        try:
            self.sockt.send(packet)
        except socket.timeout:
            raise RCONTimeoutError('Connection timed out on sending.')

    def receive(self):
        if not isinstance(self.sockt, socket.socket):
            raise RCONSocketError('There is no connection established.')

        try:
            raw_packet_size = self.sockt.recv(4)
            packet_size = struct.unpack('<I', raw_packet_size)[0]
            raw_packet = self.sockt.recv(packet_size)

            if self._is_debug_active:
                dump = ' '.join(
                    format(b, '02x')
                    for b in raw_packet_size + raw_packet
                )
                print('[DEBUG] RCON.receive (packet): {}'.format(dump))
        except socket.timeout:
            raise RCONTimeoutError('Connection timed out on receiving.')
        else:
            try:
                strings = raw_packet[8:].decode('ISO-8859-1').split('\x00')
            except UnicodeDecodeError as e:
                strings = raw_packet[8:].decode(errors='replace').split('\x00')
                if self._is_debug_active:
                    print('[DEBUG] RCON.receive (UnicodeDecodeError): {}'.format(e))

            if self._is_debug_active:
                print('[DEBUG] RCON.receive (strings): {}'.format(strings))

            response = {
                'packet_size': packet_size,
                'packet_id': struct.unpack('<I', raw_packet[0:4])[0],
                'packet_type': struct.unpack('<I', raw_packet[4:8])[0],
                'packet_body': strings[0]
            }

            # As vezes o packet vem com body sem terminador nulo
            # e sem empty string.
            if len(strings) > 1:
                response.update(empty_string=strings[1])

            return response

    def authenticate(self, password):
        if not isinstance(self.sockt, socket.socket):
            raise RCONSocketError('There is no connection established.')

        self.send(
            packet_id=AUTH_PACKET_ID,
            packet_type=SERVERDATA_AUTH,
            packet_body=password
        )

        response = self.receive()
        while response['packet_type'] != SERVERDATA_AUTH_RESPONSE:
            if self._is_debug_active:
                print('[DEBUG] RCON.authenticate (response): {}'.format(response))

            response = self.receive()

        if response['packet_id'] == MAX_PACKET_ID:  # Or -1 (0xFFFFFFFF)
            raise RCONAuthError('Invalid RCON password.')

    def execute(self, command):
        if not isinstance(self.sockt, socket.socket):
            raise RCONSocketError('There is no connection established.')

        random_id = randrange(1, MAX_PACKET_ID+1)

        # Sends the command itself.
        self.send(
            packet_id=random_id,
            packet_type=SERVERDATA_EXECCOMMAND,
            packet_body=command
        )

        # Sends an empty response too, so that we can know
        # if we have multiple packets.
        self.send(
            packet_id=0,
            packet_type=SERVERDATA_RESPONSE_VALUE,
            packet_body=''
        )

        body, response = '', self.receive()
        while response != EMPTY_RESPONSE:
            if self._is_debug_active:
                print('[DEBUG] RCON.execute (response): {}'.format(response))

            if response['packet_id'] == random_id:
                body += response['packet_body']

            response = self.receive()

        if self._is_debug_active:
            print('[DEBUG] RCON.execute (response): {}'.format(response))
            print('[DEBUG] RCON.execute (body size): {}'.format(len(body)))

        return body


if __name__ == "__main__":
    parser = OptionParser(usage=f'{__file__} -a HOST -p PORT -P password command')
    parser.add_option('-a', dest='host', help='Specifies the address of the server to connect to.')
    parser.add_option('-p', dest='port', default='27015', help='Specifies the port of the server.')
    parser.add_option('-P', dest='password', help='Specifies the rcon_password.')
    options, args = parser.parse_args()
    if not options.host or not options.port or not options.password or not args:
        os.system(sys.argv[0] + ' -h')
        sys.exit(1)

    rcon = RCON(ip=options.host, port=int(options.port), timeout=10.0)
    rcon._is_debug_active = False

    try:
        try:
            print('Connecting... ', end='')
            rcon.connect()
            print('OK')

            print('Authenticating... ', end='')
            rcon.authenticate(password=options.password)
            print('OK')

            print('Sending command... ', end='')
            command_output = rcon.execute(';'.join(args))
            print('OK')
            print('\n\n{}'.format(command_output))
        except RCONAuthError as e:
            print(f'RCONAuthError: {e}')
        except RCONTimeoutError as e:
            print(f'RCONTimeoutError: {e}')
        except RCONSocketError as e:
            print(f'RCONSocketError: {e}')
        except Exception as e:
            print(f'Exception: {e}')
    finally:
        print('Disconnecting... ', end='')
        rcon.disconnect()
        print('OK')
