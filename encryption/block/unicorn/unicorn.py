from encryption.block.base_block import BaseBlock


class UnicornA(BaseBlock):
    def __init__(self, key_length: int, key):
        super().__init__(key_length, key)

    def encrypt(self, text):
        w = [0] * 4
        tmp = [0] * 2
        int_output = [0] * 16

        for i in range(4):
            w[i] = text[i * 4] << 24
            w[i] |= text[i * 4 + 1] << 16
            w[i] |= text[i * 4 + 2] << 8
            w[i] |= text[i * 4 + 3]

        for i in range(4):
            w[i] += self.key[i * 4]

        for i in range(16):
            self.f_lin(w[2], w[3], tmp[0], tmp[1])
            tmp[0] ^= w[0]
            tmp[1] ^= w[1]
            w[0] = w[2]
            w[1] = w[3]
            w[2] = tmp[0]
            w[3] = tmp[1]

        w[0] -= self.key[(16 * 16 + 16) + 8]
        w[1] -= self.key[((16 * 16 + 16) + 12)]
        w[2] -= self.key[(16 * 16 + 16)]
        w[3] -= self.key[((16 * 16 + 16) + 4)]

        int_output[0] = (w[2] >> 24)
        int_output[1] = (w[2] >> 16)
        int_output[2] = (w[2] >> 8)
        int_output[3] = w[2]
        int_output[4] = (w[3] >> 24)
        int_output[5] = (w[3] >> 16)
        int_output[6] = (w[3] >> 8)
        int_output[7] = w[3]
        int_output[8] = (w[0] >> 24)
        int_output[9] = (w[0] >> 16)
        int_output[10] = (w[0] >> 8)
        int_output[11] = w[0]
        int_output[12] = (w[1] >> 24)
        int_output[13] = (w[1] >> 16)
        int_output[14] = (w[1] >> 8)
        int_output[15] = w[1]

        cipher = [x.to_bytes((x.bit_length() + 7) // 8, 'big') for x in int_output]

        return cipher

    def decrypt(self, text):
        w = [0] * 4
        tmp = [0] * 2
        int_output = [0] * 16

        for i in range(4):
            w[i] = text[i * 4] << 24
            w[i] |= text[i * 4 + 1] << 16
            w[i] |= text[i * 4 + 2] << 8
            w[i] |= text[i * 4 + 3]

        for i in range(4):
            w[i] += self.key[i * 4]

        for i in range(15, -1, -1):
            self.f_lin(w[2], w[3], tmp[0], tmp[1])
            tmp[0] ^= w[0]
            tmp[1] ^= w[1]
            w[0] = w[2]
            w[1] = w[3]
            w[2] = tmp[0]
            w[3] = tmp[1]

        w[0] -= self.key[(16 * 16 + 16) + 8]
        w[1] -= self.key[((16 * 16 + 16) + 12)]
        w[2] -= self.key[(16 * 16 + 16)]
        w[3] -= self.key[((16 * 16 + 16) + 4)]

        int_output[0] = (w[2] >> 24)
        int_output[1] = (w[2] >> 16)
        int_output[2] = (w[2] >> 8)
        int_output[3] = w[2]
        int_output[4] = (w[3] >> 24)
        int_output[5] = (w[3] >> 16)
        int_output[6] = (w[3] >> 8)
        int_output[7] = w[3]
        int_output[8] = (w[0] >> 24)
        int_output[9] = (w[0] >> 16)
        int_output[10] = (w[0] >> 8)
        int_output[11] = w[0]
        int_output[12] = (w[1] >> 24)
        int_output[13] = (w[1] >> 16)
        int_output[14] = (w[1] >> 8)
        int_output[15] = w[1]

        cipher = [x.to_bytes((x.bit_length() + 7) // 8, 'big') for x in int_output]

        return cipher

    def f_lin(self, ida, idb, oda, odb):
        wx0 = ida + self.key[0]
        wx1 = idb + self.key[2]
        wk0 = idb + self.key[1]
        wk1 = ida + self.key[3]
        tmp = wx0 ^ wx0 << 23 ^ wx1 >> 9 ^ wx0 >> 23 ^ wx1 << 9
        wx1 = wx1 ^ wx1 << 23 ^ wx0 >> 9 ^ wx1 >> 23 ^ wx0 << 9
        wx0 = tmp * 0x7e167289
        wx1 ^= IV[wx0 >> 24]
        wx1 *= Convert.ToInt32(0xfe21464b)
        wx0 ^= IV[wx1 >> 24]
        wx1 ^= IV[(wx0 >> 16) & 0xff]
        wx0 ^= IV[(wx1 >> 16) & 0xff]
        wx1 ^= IV[(wx0 >> 8) & 0xff]
        wx0 ^= IV[(wx1 >> 8) & 0xff]
        wx1 ^= IV[wx0 & 0xff]
        wx0 ^= IV[wx1 & 0xff]
        wk0 *= 0x7e167289
        wk1 ^= IV[wk0 >> 24]
        wk1 *= Convert.ToInt32(0xfe21464b)
        wk0 ^= IV[wk1 >> 24]
        wk0 *= Convert.ToInt32(0xfe21464b)
        wk1 ^= IV[wk0 >> 24]
        wk1 *= 0x7e167289
        wk0 ^= IV[wk1 >> 24]
        wk1 ^= IV[(wk0 >> 16) & 0xff]
        wk0 ^= IV[(wk1 >> 16) & 0xff]
        wx1 ^= IV[(wx0 >> (24 - ((wk1 & 0xc) << 1))) & 0xff]
        wx0 ^= IV[(wx1 >> (24 - ((wk1 & 0x3) * 8))) & 0xff]
        oda = wx0 ^ wk0
        odb = wx1 ^ wk0
        return ida, idb, oda, odb