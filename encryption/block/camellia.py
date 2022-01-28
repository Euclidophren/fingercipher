from encryption.block.base_block import BaseBlock


class Camellia(BaseBlock):
    def __init__(self, key_length: int, key):
        super().__init__(key_length, key)

        self.sigma1 = 0xA09E667F3BCC908B
        self.sigma2 = 0xB67AE8584CAA73B2
        self.sigma3 = 0xC6EF372FE94F82BE
        self.sigma4 = 0x54FF53A5F1D36F1C
        self.sigma5 = 0x10E527FADE682D1D
        self.sigma6 = 0xB05688C2B3E6C1FD

        self.S1 = [
            0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
            0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
            0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
            0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
            0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
            0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
            0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
            0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
            0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
            0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
            0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
            0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
            0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
            0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
            0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
            0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e
        ]
        self.S2, self.S3, self.S4 = self.sbox_generate()
        self.kl = [key[0:], key[8:]]
        self.d1, self.d2, self.ka, self.kb, self.kl, self.kr = self.generate(self.key)
        self.kw = [0] * 5
        self.ke = [0] * 7
        self.k = [0] * 25
        
    def _shift(self, bits, value, shift):
        return (value << shift) | (value >> (bits - shift))

    def _shift128(self, k, rot):
        if rot > 64:
            rot -= 64
            k[0], k[1] = k[1], k[0]

        t = k[0] >> (64 - rot)
        hi = (k[0] << rot) | (k[1] >> (64 - rot))
        lo = (k[1] << rot) | t
        return hi, lo

    def sbox_generate(self):
        size = len(self.S1)
        s2 = [0] * size
        s3 = [0] * size
        s4 = [0] * size
        for i in range(size):
            s2[i] = self._shift(8, self.S1[i], 1)
            s3[i] = self._shift(8, self.S1[i], 7)
            s4[i] = self.S1[self._shift(8, i, 1)]

        return s2, s3, s4

    def generate(self, key):
        kl, kr, ka, kb = [0] * 2, [0] * 2, [0] * 2, [0] * 2
        kl[0] = key[0:]
        kl[1] = key[8:]

        if self.key_length == 192:
            kr[0] = key[16:]
            kr[1] = ~kr[0]
        elif self.key_length == 256:
            kr[0] = key[16:]
            kr[1] = key[24:]

        d1 = (kl[0] ^ kr[0])
        d2 = (kl[1] ^ kr[1])

        d2 = d2 ^ self._f(d1, self.sigma1)
        d1 = d1 ^ self._f(d2, self.sigma2)

        d1 = d1 ^ (self.kl[0])
        d2 = d2 ^ (self.kl[1])
        d2 = d2 ^ self._f(d1, self.sigma3)
        d1 = d1 ^ self._f(d2, self.sigma4)
        ka[0] = d1
        ka[1] = d2
        d1 = (ka[0] ^ kr[0])
        d2 = (ka[1] ^ kr[1])
        d2 = d2 ^ self._f(d1, self.sigma5)
        d1 = d1 ^ self._f(d2, self.sigma6)
        kb[0] = d1
        kb[1] = d2

        return d1, d2, ka, kb, kl, kr

    def key_setup(self):
        if self.key_length == 128:
            self.kw[1], self.kw[2] = self._shift128(self.kl, 0)

            self.k[1], self.k[2] = self._shift128(self.ka, 0)
            self.k[3], self.k[4] = self._shift128(self.kl, 15)
            self.k[5], self.k[6] = self._shift128(self.ka, 15)

            self.ke[1], self.ke[2] = self._shift128(self.ka, 30)

            self.k[7], self.k[8] = self._shift128(self.kl, 45)
            self.k[9], _ = self._shift128(self.ka, 45)
            _, self.k[10] = self._shift128(self.kl, 60)
            self.k[11], self.k[12] = self._shift128(self.ka, 60)

            self.ke[3], self.ke[4] = self._shift128(self.kl, 77)

            self.k[13], self.k[14] = self._shift128(self.kl, 94)
            self.k[15], self.k[16] = self._shift128(self.ka, 94)
            self.k[17], self.k[18] = self._shift128(self.kl, 111)

            self.kw[3], self.kw[4] = self._shift128(self.ka, 111)
        else:
            self.kw[1], self.kw[2] = self._shift128(self.kl, 0)

            self.k[1], self.k[2] = self._shift128(self.kb, 0)
            self.k[3], self.k[4] = self._shift128(self.kr, 15)
            self.k[5], self.k[6] = self._shift128(self.ka, 15)

            self.ke[1], self.ke[2] = self._shift128(self.kr, 30)

            self.k[7], self.k[8] = self._shift128(self.kb, 30)
            self.k[9], self.k[10] = self._shift128(self.kl, 45)
            self.k[11], self.k[12] = self._shift128(self.ka, 45)

            self.ke[3], self.ke[4] = self._shift128(self.kl, 60)

            self.k[13], self.k[14] = self._shift128(self.kr, 60)
            self.k[15], self.k[16] = self._shift128(self.kb, 60)
            self.k[17], self.k[18] = self._shift128(self.kl, 77)

            self.ke[5], self.ke[6] = self._shift128(self.ka, 77)

            self.k[19], self.k[20] = self._shift128(self.kr, 94)
            self.k[21], self.k[22] = self._shift128(self.ka, 94)
            self.k[23], self.k[24] = self._shift128(self.kl, 111)

            self.kw[3], self.kw[4] = self._shift128(self.kb, 111)

    def _f(self, fin, ke):
        x = fin ^ ke
        t1 = self.S1[(x >> 56)]
        t2 = self.S2[(x >> 48)]
        t3 = self.S3[(x >> 40)]
        t4 = self.S4[(x >> 32)]
        t5 = self.S2[(x >> 24)]
        t6 = self.S3[(x >> 16)]
        t7 = self.S4[(x >> 8)]
        t8 = self.S1[x]
        y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
        y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
        y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
        y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
        y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
        y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
        y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
        y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
        return y1 << 56 | y2 << 48 | y3 << 40 | y4 << 32 | y5 << 24 | y6 << 16 | y7 << 8 | y8

    def _fl(self, flin, ke):
        x1 = (flin >> 32)
        x2 = (flin & 0xffffffff)
        k1 = (ke >> 32)
        k2 = (ke & 0xffffffff)
        x2 = x2 ^ self._shift(32, x1 & k1, 1)
        x1 = x1 ^ (x2 | k2)
        return x1 << 32 | x2

    def _flinv(self, flin, ke):
        y1 = (flin >> 32)
        y2 = (flin & 0xffffffff)
        k1 = (ke >> 32)
        k2 = (ke & 0xffffffff)
        y1 = y1 ^ (y2 | k2)
        y2 = y2 ^ self._shift(32, y1 & k1, 1)
        return y1 << 32 | y2

    def encrypt(self, text):
        dst = []
        d1 = text[0:]
        d2 = text[8:]

        d1 ^= self.kw[1]
        d2 ^= self.kw[2]

        d2 = d2 ^ self._f(d1, self.k[1])
        d1 = d1 ^ self._f(d2, self.k[2])
        d2 = d2 ^ self._f(d1, self.k[3])
        d1 = d1 ^ self._f(d2, self.k[4])
        d2 = d2 ^ self._f(d1, self.k[5])
        d1 = d1 ^ self._f(d2, self.k[6])

        d1 = self._fl(d1, self.ke[1])
        d2 = self._flinv(d2, self.ke[2])

        d2 = d2 ^ self._f(d1, self.k[7])
        d1 = d1 ^ self._f(d2, self.k[8])
        d2 = d2 ^ self._f(d1, self.k[9])
        d1 = d1 ^ self._f(d2, self.k[10])
        d2 = d2 ^ self._f(d1, self.k[11])
        d1 = d1 ^ self._f(d2, self.k[12])

        d1 = self._fl(d1, self.ke[3])
        d2 = self._flinv(d2, self.ke[4])

        d2 = d2 ^ self._f(d1, self.k[13])
        d1 = d1 ^ self._f(d2, self.k[14])
        d2 = d2 ^ self._f(d1, self.k[15])
        d1 = d1 ^ self._f(d2, self.k[16])
        d2 = d2 ^ self._f(d1, self.k[17])
        d1 = d1 ^ self._f(d2, self.k[18])

        if self.key_length > 128:

            d1 = self._fl(d1, self.ke[5])
            d2 = self._flinv(d2, self.ke[6])
    
            d2 = d2 ^ self._f(d1, self.k[19])
            d1 = d1 ^ self._f(d2, self.k[20])
            d2 = d2 ^ self._f(d1, self.k[21])
            d1 = d1 ^ self._f(d2, self.k[22])
            d2 = d2 ^ self._f(d1, self.k[23])
            d1 = d1 ^ self._f(d2, self.k[24])

        d2 = d2 ^ self.kw[3]
        d1 = d1 ^ self.kw[4]

        dst[0:] = d2
        dst[8:] = d1

        return dst

    def decrypt(self, text):
        dst = []

        d2 = text[0:]
        d1 = text[8:]

        d1 = d1 ^ self.kw[4]
        d2 = d2 ^ self.kw[3]

        if self.key_length > 128:
            d1 = d1 ^ self._f(d2, self.k[24])
            d2 = d2 ^ self._f(d1, self.k[23])
            d1 = d1 ^ self._f(d2, self.k[22])
            d2 = d2 ^ self._f(d1, self.k[21])
            d1 = d1 ^ self._f(d2, self.k[20])
            d2 = d2 ^ self._f(d1, self.k[19])

            d2 = self._fl(d2, self.ke[6])
            d1 = self._flinv(d1, self.ke[5])

        d1 = d1 ^ self._f(d2, self.k[18])
        d2 = d2 ^ self._f(d1, self.k[17])
        d1 = d1 ^ self._f(d2, self.k[16])
        d2 = d2 ^ self._f(d1, self.k[15])
        d1 = d1 ^ self._f(d2, self.k[14])
        d2 = d2 ^ self._f(d1, self.k[13])

        d2 = self._fl(d2, self.ke[4])
        d1 = self._flinv(d1, self.ke[3])

        d1 = d1 ^ self._f(d2, self.k[12])
        d2 = d2 ^ self._f(d1, self.k[11])
        d1 = d1 ^ self._f(d2, self.k[10])
        d2 = d2 ^ self._f(d1, self.k[9])
        d1 = d1 ^ self._f(d2, self.k[8])
        d2 = d2 ^ self._f(d1, self.k[7])

        d2 = self._fl(d2, self.ke[2])
        d1 = self._flinv(d1, self.ke[1])

        d1 = d1 ^ self._f(d2, self.k[6])
        d2 = d2 ^ self._f(d1, self.k[5])
        d1 = d1 ^ self._f(d2, self.k[4])
        d2 = d2 ^ self._f(d1, self.k[3])
        d1 = d1 ^ self._f(d2, self.k[2])
        d2 = d2 ^ self._f(d1, self.k[1])

        d2 ^= self.kw[2]
        d1 ^= self.kw[1]

        dst[0:] = d2
        dst[8:] = d1

        return dst
