import os
from elftools import *
# pip3 install cmake lief

class Patcher:
    binary: bytes
    patched_filename: str
    filename : str

    def __init__(self, filename: str, suffix: str = ".patched"):
        self.filename=filename
        with open(filename, 'rb') as f:
            self.binary = f.read()
            self.patched_filename = filename + suffix

    def patch(self, address, size, value):
        assert len(self.binary) >= address + size
        value = self._force_bytes(value)
        assert len(value) == size
        assert type(value) == bytes
        self.binary = self.binary[:address] + value + self.binary[address + size:]

    def copy_to_patch(self, to_address, from_address, size):
        """
        copy binary bytes
        :param to_address:
        :param from_address:
        :param size:
        """
        assert len(self.binary) >= from_address + size

        self.patch(to_address, size, self.binary[from_address:from_address + size])

    @staticmethod
    def _force_bytes(data, encoding="utf-8"):
        if isinstance(data, bytes):
            return data

        if isinstance(data, str):
            # return data.encode(encoding)
            return data.encode("iso-8859-15")  # same as latin1

        if isinstance(data, list):
            # keystone assemble only
            return bytes(data)

        return data

    def write_patch_to_file(self):
        with open(self.patched_filename, 'wb') as f:
            f.write(self.binary)
