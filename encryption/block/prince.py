from encryption.block.base_block import BaseBlock


class Prince(BaseBlock):
    def __init__(self, key_length, key):
        super().__init__(key_length, key)
        self.round_constant = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x31, 0x91, 0xa8, 0xe2, 0x30, 0x07, 0x37, 0x44,
            0x4a, 0x90, 0x83, 0x22, 0x92, 0xf9, 0x13, 0x0d,
            0x80, 0xe2, 0xaf, 0x89, 0xce, 0xe4, 0xc6, 0x98,
            0x54, 0x82, 0x12, 0x6e, 0x83, 0x0d, 0x31, 0x77,
            0xeb, 0x45, 0x66, 0xfc, 0x43, 0x9e, 0xc0, 0xc6,
            0xe7, 0x8f, 0xf4, 0x87, 0xdf, 0x59, 0xc5, 0x1b,
            0x58, 0x48, 0x80, 0x15, 0x1f, 0xca, 0x34, 0xaa,
            0x8c, 0x28, 0x3d, 0xf2, 0x52, 0x23, 0xc3, 0x45,
            0x46, 0x5a, 0x11, 0x59, 0x0e, 0x3e, 0x16, 0xd0,
            0x3d, 0x5b, 0x3a, 0x99, 0xac, 0xc0, 0x32, 0x99,
            0x0c, 0xca, 0x92, 0x7b, 0x9c, 0xc7, 0x05, 0xdd
        ]
        self.s_box = [
            0x0B, 0x0F, 0x03, 0x02, 0x0A, 0x0C, 0x09, 0x01, 0x06, 0x07, 0x08, 0x00, 0x0E, 0x05, 0x0D, 0x04
        ]
        self.inv_s_box = [
            0x0B, 0x07, 0x03, 0x02, 0x0F, 0x0D, 0x08, 0x09, 0x0A, 0x06, 0x04, 0x00, 0x05, 0x0E, 0x0C, 0x01
        ]
        self.state = None
        self.round = None

    def key_setup(self, key):
        subkey = [0] * 8
        subkey[0] = (key[0] >> 1) | (key[1] << 7)
        subkey[1] = (key[1] >> 1) | (key[2] << 7)
        subkey[2] = (key[2] >> 1) | (key[3] << 7)
        subkey[3] = (key[3] >> 1) | (key[4] << 7)
        subkey[4] = (key[4] >> 1) | (key[5] << 7)
        subkey[5] = (key[5] >> 1) | (key[6] << 7)
        subkey[6] = (key[6] >> 1) | (key[7] << 7)
        subkey[7] = (key[7] >> 1) | (key[0] << 7)
        subkey[7] ^= (key[7] & 0x10)
        return subkey

    def add_round_key(self, key):
        i = 0
        while i < self.round:
            self.state[i] ^= key[8 + i]
            i += 1

    def s_box_layer(self):
        i = 0
        while i < self.round:
            self.state[i] = self.s_box[self.state[i] >> 4] << 4 | self.s_box[i] & 0x0F
            i += 1
    
    def s_box_layer_inv(self):
        i = 0
        while i < self.round:
            self.state[i] = self.inv_s_box[self.state[i] >> 4] << 4 | self.s_box[i] & 0x0F
            i += 1

    def _m_layer(self):
        s0 = self.state[0]
        s2 = self.state[2]
        s4 = self.state[4]
        s6 = self.state[6]
        self.state[0] = (s0 & 0xD7) ^ (self.state[1] & 0x7D) ^ (s0 >> 4 & 0x0B) ^ \
                        (self.state[1] >> 4 & 0x0E) ^ (s0 << 4 & 0xB0) ^ (self.state[1] << 4 & 0xE0)
        self.state[1] = (s0 & 0x7D) ^ (self.state[1] & 0xD7) ^ (s0 >> 4 & 0x0E) ^ \
                        (self.state[1] >> 4 & 0x0B) ^ (s0 << 4 & 0xE0) ^ (self.state[1] << 4 & 0xB0)
        self.state[2] = (s2 & 0xEB) ^ (self.state[3] & 0xBE) ^ (s2 >> 4 & 0x0D) ^ \
                        (self.state[3] >> 4 & 0x07) ^ (s2 << 4 & 0xD0) ^ (self.state[3] << 4 & 0x70)
        self.state[3] = (s2 & 0xBE) ^ (self.state[3] & 0xEB) ^ (s2 >> 4 & 0x07) ^ \
                        (self.state[3] >> 4 & 0x0D) ^ (s2 << 4 & 0x70) ^ (self.state[3] << 4 & 0xD0)
        self.state[4] = (s4 & 0xEB) ^ (self.state[5] & 0xBE) ^ (s4 >> 4 & 0x0D) ^ \
                        (self.state[5] >> 4 & 0x07) ^ (s4 << 4 & 0xD0) ^ (self.state[5] << 4 & 0x70)
        self.state[5] = (s4 & 0xBE) ^ (self.state[5] & 0xEB) ^ (s4 >> 4 & 0x07) ^ \
                        (self.state[5] >> 4 & 0x0D) ^ (s4 << 4 & 0x70) ^ (self.state[5] << 4 & 0xD0)
        self.state[6] = (s6 & 0xD7) ^ (self.state[7] & 0x7D) ^ (s6 >> 4 & 0x0B) ^ \
                        (self.state[7] >> 4 & 0x0E) ^ (s6 << 4 & 0xB0) ^ (self.state[7] << 4 & 0xE0)
        self.state[7] = (s6 & 0x7D) ^ (self.state[7] & 0xD7) ^ (s6 >> 4 & 0x0E) ^ \
                        (self.state[7] >> 4 & 0x0B) ^ (s6 << 4 & 0xE0) ^ (self.state[7] << 4 & 0xB0)

    def _shift_row(self):
        temp = [0] * 8
        temp[0] = (self.state[0] & 0x0F) | (self.state[2] & 0xF0)
        temp[1] = (self.state[5] & 0x0F) | (self.state[7] & 0xF0)
        temp[2] = (self.state[2] & 0x0F) | (self.state[4] & 0xF0)
        temp[3] = (self.state[7] & 0x0F) | (self.state[1] & 0xF0)
        temp[4] = (self.state[4] & 0x0F) | (self.state[6] & 0xF0)
        temp[5] = (self.state[1] & 0x0F) | (self.state[3] & 0xF0)
        temp[6] = (self.state[6] & 0x0F) | (self.state[0] & 0xF0)
        temp[7] = (self.state[3] & 0x0F) | (self.state[5] & 0xF0)

        i = 0
        while i < self.round:
            self.state[i] = temp[i]
            i += 1

    def _inv_shift_row(self):
        temp = [0] * 8
        temp[0] = (self.state[0] & 0x0F) | (self.state[6] & 0xF0)
        temp[1] = (self.state[5] & 0x0F) | (self.state[3] & 0xF0)
        temp[2] = (self.state[2] & 0x0F) | (self.state[0] & 0xF0)
        temp[3] = (self.state[7] & 0x0F) | (self.state[5] & 0xF0)
        temp[4] = (self.state[4] & 0x0F) | (self.state[2] & 0xF0)
        temp[5] = (self.state[1] & 0x0F) | (self.state[7] & 0xF0)
        temp[6] = (self.state[6] & 0x0F) | (self.state[4] & 0xF0)
        temp[7] = (self.state[3] & 0x0F) | (self.state[1] & 0xF0)

        i = 0
        while i < self.round:
            self.state[i] = temp[i]
            i += 1

    def m_layer(self):
        self._m_layer()
        self._shift_row()

    def _add_round_constant(self):
        i = 0
        while i < self.round:
            self.state[0] ^= self.round_constant[8 * self.round + i]
            i += 1

    def inv_m_layer(self):
        self._inv_shift_row()
        self._m_layer()

    def _crypt(self, key):
        for r in range(1, 6):
            self.s_box_layer()
            self._m_layer()
            self._add_round_constant()
            self.add_round_key(key)
        self.s_box_layer()
        self._m_layer()
        self.s_box_layer_inv()

        for r in range(11):
            self.add_round_key(key)
            self._add_round_constant()
            self.inv_m_layer()
            self.s_box_layer_inv()

        self._add_round_constant()
        self.add_round_key(key)

    @staticmethod
    def _key_ops(key):
        key[8] ^= 0x0c
        key[9] ^= 0xca
        key[10] ^= 0x92
        key[11] ^= 0x7b
        key[12] ^= 0x9c
        key[13] ^= 0xc7
        key[14] ^= 0x05
        key[15] ^= 0xdd

    def encrypt(self, text, key):
        for r in range(8):
            self.state[r] ^= key[r]

        subkey = self.key_setup(key)

        for r in range(self.round):
            self.state[r] ^= subkey[r]

    def decrypt(self, text, key):
        temp = [0] * 8
        subkey = self.key_setup(key)
        for r in range(8):
            temp[r] = subkey[r]
            subkey[r] = key[r]
            key[r] = temp[r]
            self.state[r] ^= key[r]

        self._key_ops(key)

        for r in range(self.round):
            self.state[r] ^= subkey[r]

        self._key_ops(key)