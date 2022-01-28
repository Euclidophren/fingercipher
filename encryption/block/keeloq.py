from encryption import BaseBlock

LUT = 0x3A5C742E


class KeeLoq(BaseBlock):
    def __init__(self, key_length: int, key):
        super().__init__(key_length, key)

    def encrypt(self, block: int, key: int) -> int:
        for i in range(528):
            lutkey = (block >> 1) & 1 | (block >> 8) & 2 | (block >> 18) & 4 | (block >> 23) & 8 | (block >> 27) & 16
            msb = (block >> 16 & 1) ^ (block & 1) ^ (LUT >> lutkey & 1) ^ (key & 1)
            block = msb << 31 | block >> 1
            key = (key & 1) << 63 | key >> 1

        return block

    def decrypt(self, block: int, key: int) -> int:
        for i in range(528):
            lutkey = (block >> 0) & 1 | (block >> 7) & 2 | (block >> 17) & 4 | (block >> 22) & 8 | (block >> 26) & 16
            lsb = (block >> 31) ^ (block >> 15 & 1) ^ (LUT >> lutkey & 1) ^ (key >> 15 & 1)
            block = (block & 0x7FFFFFFF) << 1 | lsb
            key = (key & 0x7FFFFFFFFFFFFFFF) << 1 | key >> 63
        return block
