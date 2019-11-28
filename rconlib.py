import struct
import socket

# On sending packets.
SERVERDATA_AUTH = 3
SERVERDATA_EXECCOMMAND = 2

# On receiving packets.
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_RESPONSE_VALUE = 0

NOT_IMPLEMENTED = "This hasn't been implemented yet."


class RCONError(Exception):
    pass


class RCONPacket:
    def __init__(self):
        raise NotImplementedError(NOT_IMPLEMENTED)


class RCON:
    def __init__(self, ip, port=27015, timeout=10.0):
        self.ip = ip
        self.port = port
        self._timeout = timeout
        self.sockt = None
        self._is_debug_active = False
        self.sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sockt.settimeout(self._timeout)

    def connect(self):
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
        self.sockt.close()
        self.sockt = None

    def send(self, packet_id, packet_type, body):
        null_terminator = b'\x00'
        empty_string = b'' + null_terminator
        packet_id = struct.pack('<I', packet_id)
        packet_type = struct.pack('<I', packet_type)
        body = bytes(body, 'ascii') + null_terminator
        packet = packet_id + packet_type + body + empty_string
        size = struct.pack('<I', len(packet))
        packet = size + packet

        if self._is_debug_active:
            dump = ' '.join(format(b, '02x') for b in packet)
            print('DEBUG (RCON.send): {}'.format(dump))

        try:
            self.sockt.send(packet)
        except socket.timeout:
            raise RCONError('Connection timed out.')

    def receive(self):
        raise NotImplementedError(NOT_IMPLEMENTED)

    def authenticate(self, password):
        self.send(packet_id=1001, packet_type=SERVERDATA_AUTH, body=password)


if __name__ == "__main__":

    rcon = RCON(ip='my-ip-server')
    rcon._is_debug_active = True

    rcon.connect()
    try:
        rcon.authenticate(password='my-rcon-password')
    finally:
        rcon.disconnect()

    rcon.receive()
