from encryption.block.base_block import BaseBlock
from typing import List


class DES(BaseBlock):
    def __init__(self, key_length: int, key):
        super().__init__(key_length, key)

    def permutation(self, L: List[str], T: List[str]) -> List[str]:
        """returns permuted list based on table T:List[str]"""
        new_L = L.copy()
        for i in range(len(T)):
            new_L[i] = L[T[i] - 1]

        return new_L

    def generate_bit(text: str) -> List[str]:
        """Convert characters to 8 bit utf-8,
            integers are converted to string
        """
        text = list(bytes(str(text), 'utf-8'))
        b_text = []
        for x in text:
            b = bin(x)[2:]
            if len(b) < 8:
                for _ in range(8 - len(b)):
                    b = '0' + b
            byte = list(b)
            for bit in byte:
                b_text.append(bit)
        return b_text

    def readFile(self, path: str) -> list:
        with open(path, 'rb') as file:
            b_file = list(file.read())
            b_text = []
            for x in b_file:
                b = bin(x)[2:]
                if len(b) < 8:
                    for _ in range(8 - len(b)):
                        b = '0' + b
                byte = list(b)
                for bit in byte:
                    b_text.append(bit)
            return b_text

    def intTObin(self, i: int) -> List[str]:
        """ result of s_boxes are extended to 4 bits
        """
        s = bin(i)
        l = []
        s1 = ''
        if len(s[2:]) < 4:
            for _ in range(4 - len(s[2:])):
                s1 = s1 + '0'
        s1 = s1 + s[2:]
        for x in s1:
            l.append(x)
        return l

    def binList(self, l: List[str]) -> int:
        """
        convert l:List[str] to int for usage S_box
        """
        for i in range(len(l)):
            l[i] = str(l[i])
        return int(''.join(l), 2)

    def bit_rotation(self, n: int, b_key: List[str]) -> List[str]:
        """breaks the list into 2 and rotate each by n:int times
        """
        left = b_key[:len(b_key) // 2].copy()
        right = b_key[(len(b_key) // 2):].copy()
        for _ in range(n):
            left.insert(0, left[-1])
            left.pop(-1)
            right.insert(0, right[-1])
            right.pop(-1)
        for x in right:
            left.append(x)
        return left

    def subkey_generation(self, b_key: List[str]) -> List[List[str]]:
        """
            returns list of 16 subkeys of size 48
        """
        shift = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28]
        subkeys = []
        for i in range(16):
            subkeys.append(self.bit_rotation(shift[i], b_key))
            self.permutation(subkeys[i], Table.PC2)
            subkeys[i] = subkeys[i][:48]
        return subkeys

    def key_generation(self, key: str) -> List[List[str]]:
        """ generate main key b_key and returns subkeys using subkey generator
        """
        b_key = self.generate_bit(key)
        while len(b_key) < 64:
            print('short key, Enter new KEY:')
            b_key = self.generate_bit(input())
        # trim to 64 bits
        if len(b_key) > 64:
            b_key = b_key[:64]
        # permute key
        b_key = self.permutation(b_key, Table.PC1)
        # key length to 56
        b_key = b_key[:56]
        subkey = self.subkey_generation(b_key)
        return subkey

    def s_box_replacement(self, right: List[str]) -> List[str]:
        r = []
        for x in range(8):
            r.append(right[x * 6:(x + 1) * 6])
        for x in range(len(r)):
            r[x] = Table.S_box[x][self.binList(r[x])]
            r[x] = self.intTObin(r[x])
        for x in r[1:]:
            for b in x:
                r[0].append(b)
        return r[0]

    def extend_right(self, right: list) -> list:
        """
        return expanded right permutation(right, Table.E)
        """
        for _ in range(16):
            right.append(0)
        return self.permutation(right, Table.E)

    def fnc(self, right: list, subkey: list) -> List[int]:
        e_right = self.extend_right(right)
        r = []
        for i in range(len(e_right)):
            e_right[i] = int(e_right[i])

        for i in range(len(subkey)):
            subkey[i] = int(subkey[i])

        for i in range(len(subkey)):
            r.append(e_right[i] ^ subkey[i])
        r = self.s_box_replacement(r)
        r = self.permutation(r, Table.P)
        return r

    def xor_list(self, L1: list, L2: list) -> list:
        l = []
        for i in range(len(L1)):
            l.append(L1[i] ^ L2[i])
        return l

    def strtobin_list(self, str1: list) -> List[int]:
        for i in range(len(str1)):
            str1[i] = int(str1[i])
        return str1

    def _encrypt(self, plaintext: str, key) -> list:
        subkeys = self.key_generation(key)
        plain_list = []
        for x in plaintext:
            plain_list.append(x)
        plaintext = plain_list
        blocks = []
        # create blocks
        for i in range(len(plaintext) // 64):
            blocks.append(plaintext[i * 64:(i + 1) * 64])
        encrypt_blocks = []
        for block in blocks:
            block = self.permutation(block, Table.IP)
            for i in range(16):
                left = block[:32].copy()
                right = block[32:].copy()
                block[:32] = right
                block[32:] = self.xor_list(self.strtobin_list(left),
                                           self.strtobin_list(self.fnc(right, subkeys[i])))
            block = self.permutation(block, Table.IP_inv)
            for x in block:
                encrypt_blocks.append(x)
        return encrypt_blocks

    def _decrypt(self, crypt: list, key) -> list:
        subkeys = self.key_generation(key)
        blocks = []
        for i in range(len(crypt) // 64):
            block = []
            for x in range(64):
                block.append(crypt[i * 64 + x])
            blocks.append(block)
        plaintext = []
        for block in blocks:
            block = self.permutation(block, Table.IP)
            for i in range(16):
                left = block[:32].copy()
                right = block[32:].copy()
                block[32:] = left
                block[:32] = self.xor_list(self.strtobin_list(right),
                                           self.strtobin_list(self.fnc(left, subkeys[15 - i])))
            block = self.permutation(block, Table.IP_inv)
            for x in block:
                plaintext.append(x)
        return plaintext


