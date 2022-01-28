from encryption.block.DES.des import DES


class DESX(DES):
    def xor(self, text: str, key) -> list:
        key = self.strtobin_list(self.generate_bit(key))[:64]
        b_text = []
        for x in text:
            b_text.append(int(x))

        final_text = []
        for i in range(len(b_text) // 64):
            x1 = self.xor_list(b_text[i * 64:(i + 1) * 64], key)
            for x in x1:
                final_text.append(x)
        return final_text

    def DESX_encrypt(self, plaintext: str, key0, key1, key2) -> list:
        final_plaintext = self.xor(plaintext, key0)
        e_text = self._encrypt(final_plaintext, key1)
        final_e_text = self.xor(e_text, key2)
        return final_e_text

    def DESX_decrypt(self, e_text: list, key0, key1, key2) -> list:
        f_e_text = self.xor(e_text, key2)
        plaintest = self._decrypt(f_e_text, key1)
        f_plaintext = self.xor(plaintest, key0)
        return f_plaintext
