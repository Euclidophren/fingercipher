from encryption.block.base_block import BaseBlock
from encryption.block.kasumi import *


def _bitlen(x):
    return len(bin(x)) - 2


def _shift(x, s):
    return ((x << s) & 0xFFFF) | (x >> (16 - s))


def _mod(x):
    return ((x - 1) % 8) + 1


class Kasumi(BaseBlock):
    def __init__(self, key):
        super().__init__(key_length=128, key=key)
        self.key_KL1 = [0] * 9
        self.key_KL2 = [0] * 9
        self.key_KO1 = [0] * 9
        self.key_KO2 = [0] * 9
        self.key_KO3 = [0] * 9
        self.key_KI1 = [0] * 9
        self.key_KI2 = [0] * 9
        self.key_KI3 = [0] * 9
        self.S7 = S7
        self.S9 = S9

    def set_key(self, key):
        u_key = [0] * 9
        key_prime = [0] * 9
        s = [0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210]

        for i in range(8):
            u_key[i] = (key >> (16 * (8 - i))) & 0xFFFF
            key_prime[i] = u_key[i] ^ s[i]

        for i in range(8):
            self.key_KL1[i] = _shift(key[_mod(i)], 1)
            self.key_KL2[i] = key_prime[_mod(i + 2) & 7]
            self.key_KO1[i] = _shift(key[_mod(i + 1) & 7], 5)
            self.key_KO2[i] = _shift(key[_mod(i + 5) & 7], 8)
            self.key_KO3[i] = _shift(key[_mod(i + 6) & 7], 13)
            self.key_KI1[i] = key_prime[_mod(i + 4) & 7]
            self.key_KI2[i] = key_prime[_mod(i + 3) & 7]
            self.key_KI3[i] = key_prime[_mod(i + 7) & 7]

    def _FI(self, text, round_key):

        left = text >> 7
        right = text & 0b1111111

        round_key_1 = round_key >> 9
        round_key_2 = round_key & 0b111111111

        tmp_l = right
        tmp_r = S9[left] ^ right

        left = tmp_r ^ round_key_2
        right = S7[tmp_l] ^ (tmp_r & 0b1111111) ^ round_key_1

        tmp_l = right
        tmp_r = S9[left] ^ right

        left = S7[tmp_l] ^ (tmp_r & 0b1111111)
        right = tmp_r

        return (left << 9) | right

    def _FO(self, text, round_i):
        in_left = text >> 16
        in_right = text & 0xFFFF

        in_left ^= self.key_KO1[round_i]
        in_left = self._FI(in_left, self.key_KI1[round_i]) ^ in_right

        in_right ^= self.key_KO2[round_i]
        in_right = self._FI(in_right, self.key_KI2[round_i]) ^ in_left

        in_left ^= self.key_KO3[round_i]
        in_left = self._FI(in_left, self.key_KI3[round_i]) ^ in_right

        return (in_right << 16) | in_left

    def _FL(self, text, round_i):
        in_left = text >> 16
        in_right = text & 0xFFFF
        out_right = in_right ^ _shift(in_left & self.key_KL1[round_i], 1)
        out_left = in_left ^ _shift(out_right | self.key_KL2[round_i], 1)
        return (out_left << 16) | out_right

    def fun_f(self, text, round_i):
        if round_i % 2 == 1:
            state = self._FL(text, round_i)
            output = self._FO(state, round_i)
        else:
            state = self._FO(text, round_i)
            output = self._FL(state, round_i)
        return output

    def enc_1r(self, in_left, in_right, round_i):
        out_right = in_left
        out_left = in_right ^ self.fun_f(in_left, round_i)
        return out_left, out_right

    def dec_1r(self, in_left, in_right, round_i):
        out_left = in_right
        out_right = self.fun_f(in_right, round_i) ^ in_left
        return out_left, out_right

    def encrypt(self, plaintext):
        left = plaintext >> 32
        right = plaintext & 0xFFFFFFFF
        for i in range(8):
            left, right = self.enc_1r(left, right, i)
        return (left << 32) | right

    def decrypt(self, ciphertext):
        left = ciphertext >> 32
        right = ciphertext & 0xFFFFFFFF
        for i in range(8, 0, -1):
            left, right = self.dec_1r(left, right, i)
        return (left << 32) | right
