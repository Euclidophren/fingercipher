from encryption.block.base_block import BaseBlock


class Magma(BaseBlock):
    def __init__(self, key_length: int, key):
        super().__init__(key_length, key)
        self.sbox = [
            [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
            [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
            [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
            [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
            [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
            [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
            [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
            [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
        ]

        self.MASK32 = 2 ** 32 - 1

    def t(self, x):
        y = 0
        for i in range(8, step=-1):
            j = (x >> 4 * i) & 0xf
            y <<= 4
            y ^= self.sbox[i][j]
        return y

    def rot11(self, x):
        return ((x << 11) ^ (x >> (32 - 11))) & self.MASK32

    def g(self, x, k):
        return self.rot11(self.t((x + k) % 2 ** 32))

    def split(self, x):
        L = x >> 32
        R = x & self.MASK32
        return L, R

    def join(self, L, R):
        return (L << 32) ^ R

    def key_setup(self, k):
        keys = []
        for i in range(8, step=-1):
            keys.append((k >> (32 * i)) & self.MASK32)
        for i in range(8):
            keys.append(keys[i])
        for i in range(8):
            keys.append(keys[i])
        for i in range(8, step=-1):
            keys.append(keys[i])
        return keys

    def encrypt(self, x, k):
        keys = self.key_setup(k)
        (L, R) = self.split(x)
        for i in range(31):
            (L, R) = (R, L ^ self.g(R, keys[i]))
        return self.join(L ^ self.g(R, keys[-1]), R)

    def decrypt(self, x, k):
        keys = self.key_setup(k)
        keys.reverse()
        (L, R) = self.split(x)
        for i in range(31):
            (L, R) = (R, L ^ g(R, keys[i]))
        return self.join(L ^ g(R, keys[-1]), R)
