from lib import socks
import struct

class TFTPClient:
    def __init__(self, target, port, socks_client):
        self.target = target
        self.port = port
        self.socks_client = socks_client

    def get_file(self, filename):
        self.socks_client.send(b'\x00\x01' + bytes(filename, 'ascii')  + b'\x00' + b'octet' + b'\x00', (self.target, self.port))
        try:
            data = self.socks_client.recv(9076)
        except Exception:
            print("[!] TFTP request timed out waiting for first block")
            return None

        (opcode, block) = struct.unpack(">HH", data[:4])
        if opcode != 3:
            print("[!] Invalid opcode from TFTP server")
            return None

        filedata = data[4:]

        # If first block is short, file fits in one packet
        if len(data) < 516:
            return filedata

        # Iterate through remaining data blocks
        while True:
            self.socks_client.send(b'\x00\x04' + block.to_bytes(2, 'big'), (self.target, self.port))
            try:
                data = self.socks_client.recv(9076)
            except Exception:
                # Timeout or error — return what we have
                return filedata

            (opcode, block) = struct.unpack(">HH", data[:4])

            if opcode != 3:
                print("[!] Invalid opcode from TFTP server")
                return filedata

            filedata += data[4:]

            if len(data) < 516:
                # Last block — end of file
                return filedata

        return filedata
