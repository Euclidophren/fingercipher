from __future__ import print_function

from encryption.block import BaseBlock


class Present(BaseBlock):
    def __init__(self, key_length: int, key):

        super().__init__(key_length, key)

        self.s_box = (0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2)

        self.inv_s_box = (0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA)

        self.p_layer_order = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53, 6,
                         22, 38,
                         54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44,
                         60, 13,
                         29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]

        self.block_size = 64

        self.ROUND_LIMIT = 32

    def round_function(self, state, key):
        new_state = state ^ key
        state_nibs = []
        for x in range(0, self.block_size, 4):
            nib = (new_state >> x) & 0xF
            sb_nib = self.s_box[nib]
            state_nibs.append(sb_nib)
        state_bits = []
        for y in state_nibs:
            nib_bits = [1 if t == '1' else 0 for t in format(y, '04b')[::-1]]
            state_bits += nib_bits
        state_p_layer = [0 for _ in range(64)]
        for p_index, std_bits in enumerate(state_bits):
            state_p_layer[self.p_layer_order[p_index]] = std_bits
        round_output = 0
        for index, ind_bit in enumerate(state_p_layer):
            round_output += (ind_bit << index)
        return round_output

    def key_function_80(self, key, round_count):
        r = [1 if t == '1' else 0 for t in format(key, '080b')[::-1]]
        h = r[-61:] + r[:-61]
        round_key_int = 0
        for index, ind_bit in enumerate(h):
            round_key_int += (ind_bit << index)
        upper_nibble = round_key_int >> 76
        upper_nibble = self.s_box[upper_nibble]
        xor_portion = ((round_key_int >> 15) & 0x1F) ^ round_count
        round_key_int = (round_key_int & 0x0FFFFFFFFFFFFFF07FFF) + (upper_nibble << 76) + (xor_portion << 15)
        return round_key_int

    def key_function_128(self, key, round_count):
        r = [1 if t == '1' else 0 for t in format(key, '0128b')[::-1]]
        h = r[-61:] + r[:-61]
        round_key_int = 0
        for index, ind_bit in enumerate(h):
            round_key_int += (ind_bit << index)
        upper_nibble = (round_key_int >> 124) & 0xF
        second_nibble = (round_key_int >> 120) & 0xF
        upper_nibble = self.s_box[upper_nibble]
        second_nibble = self.s_box[second_nibble]
        xor_portion = ((round_key_int >> 62) & 0x1F) ^ round_count
        round_key_int = (round_key_int & 0x00FFFFFFFFFFFFF83FFFFFFFFFFFFFFF) + (upper_nibble << 124) + (
                    second_nibble << 120) + (xor_portion << 62)
        return round_key_int
