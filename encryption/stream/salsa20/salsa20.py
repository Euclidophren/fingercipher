from encryption.stream.base_stream import BaseStream


class Salsa20(BaseStream):
    def __init__(self, key_length, key):
        super().__init__(key_length, key)
        self.sigma = [
            [101, 120, 112, 97],
            [110, 100, 32, 51],
            [50, 45, 98, 121],
            [116, 101, 32, 107]
        ]
        self.tau = [
            [101, 120, 112, 97],
            [110, 100, 32, 49],
            [54, 45, 98, 121],
            [116, 101, 32, 107]
        ]

    def _shift(self, value, shift):
        return (value << shift) | (value >> (32 - shift))

    def _quarter_round(self, y_0, y_1, y_2, y_3):
        y_1 ^= self._shift(y_0 + y_3, 7)
        y_2 ^= self._shift(y_1 + y_0, 9)
        y_3 ^= self._shift(y_2 + y_1, 13)
        y_0 ^= self._shift(y_3 + y_2, 18)

    def row_round(self, y):
        self._quarter_round(y[0], y[1], y[2], y[3])
        self._quarter_round(y[5], y[6], y[7], y[4])
        self._quarter_round(y[10], y[11], y[8], y[9])
        self._quarter_round(y[15], y[12], y[13], y[14])

    def column_round(self, x):
        self._quarter_round(x[0], x[4], x[8], x[12])
        self._quarter_round(x[5], x[9], x[13], x[1])
        self._quarter_round(x[10], x[14], x[2], x[6])
        self._quarter_round(x[15], x[3], x[7], x[11])

    def double_round(self, x):
        self.column_round(x)
        self.row_round(x)

    def littleendian(self, b):
        return b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24)

    def rev_littleendian(self, b, w):
        b[0] = w
        b[1] = w >> 8
        b[2] = w >> 16
        b[3] = w >> 24

    def _hash(self, key_stream):
        x = [0] * 16
        z = [0] * 16
        for i in range(16):
            x[i] = z[i] = self.littleendian(key_stream + (4 * i))
        for i in range(10):
            self.double_round(z)
        for i in range(16):
            z[i] += x[i]
            self.rev_littleendian(key_stream + (4 * i), z[i])

    def expand_key(self, key_stream, key, nonce):
        expand = self.sigma if self.key_length == 16 else self.tau
        for i in range(64):
            for j in range(4):
                key[i + j] = expand[i // 20][j]

        for i in range(16):
            key_stream[4 + i] = key[i]
            key_stream[44 + i] = key[i]
            key_stream[24 + i] = nonce[i]

        self._hash(key_stream)

    def encrypt(self, key, nonce):
        key_half = self.key_length // 2
        exp = self.sigma if self.key_length == 16 else self.tau
        block_counter = [0] * 8
        return self._hash(exp[0] + key[:key_half] + exp[1] + nonce +
                          block_counter + exp[2] + key[key_half:] + exp[3])

    def _xor(self, message, nonce, key):
        key_half = self.key_length // 2
        exp = self.sigma if self.key_length == 16 else self.tau
        _nonce = list(nonce)
        _key = list(key)
        block_counter = [0] * 8
        enc_list = [a ^ b for a, b in
                    zip(self._hash(exp[0] + key[:key_half] + exp[1] + nonce +
                          block_counter + exp[2] + key[key_half:] + exp[3]), list(message))]
        return bytearray(enc_list)
