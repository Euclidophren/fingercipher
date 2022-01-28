from encryption.block.DES.des import DES


class DES3(DES):
    def encrypt(self, plaintext: str, key1, key2, key3) -> list:
        return self._encrypt(self._decrypt(self._encrypt(plaintext, key1), key2), key3)

    def decrypt(self, e_text: list, key1, key2, key3) -> list:
        return self._decrypt(self._encrypt(self._decrypt(e_text, key3), key2), key1)