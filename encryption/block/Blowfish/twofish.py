from encryption.block.base_block import BaseBlock


class TwoFish(BaseBlock):
    def __init__(self, key_length: int, key):
        super().__init__(key_length, key)

        self.l_key = [0] * 40
        self.s_key = [0] * 4

        self.tab_5b = [0, 0x0169 >> 2, 0x0169 >> 1, (0x0169 >> 1) ^ (0x0169 >> 2)]
        self.tab_ef = [0, (0x0169 >> 1) ^ (0x0169 >> 2), 0x0169 >> 1, 0x0169 >> 2]

        self.ror4 = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
        self.ashx = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]

        self.qt0 = [
            [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
            [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5]
        ]

        self.qt1 = [
            [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
            [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8]
        ]

        self.qt2 = [
            [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
            [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15]
        ]

        self.qt3 = [
            [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
            [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10]
        ]

    def ffm_01(self, x):
        return x

    def ffm_5b(self, x):
        return x ^ (x >> 2) ^ self.tab_5b[x & 3]

    def ffm_ef(self, x):
        return x ^ (x >> 1) ^ (x >> 2) ^ self.tab_ef[x & 3]

    def qp(self, n, x):
        a0 = x >> 4
        b0 = x & 15
        a1 = a0 ^ b0
        b1 = self.ror4[b0] ^ self.ashx[a0]
        a2 = self.qt0[n][a1]
        b2 = self.qt1[n][b1]
        a3 = a2 ^ b2
        b3 = self.ror4[b2] ^ self.ashx[a2]
        a4 = self.qt2[n][a3]
        b4 = self.qt3[n][b3]
        return (b4 << 4) | a4

    def gen_mtab(self):
        m_tab = [[0] * 256 for _ in range(4)]
        for i in range(256):
            f01 = self.qp(1, i)
            f5b = self.ffm_5b(f01)
            fef = self.ffm_ef(f01)
            m_tab[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24)
            m_tab[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24)

            f01 = self.qp(0, i)
            f5b = self.ffm_5b(f01)
            fef = self.ffm_ef(f01)
            m_tab[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24)
            m_tab[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24)

        return m_tab

