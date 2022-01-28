from ctypes import c_uint32 as uint32
from struct import pack, unpack


from encryption.block.base_block import BaseBlock


class XTEA(BaseBlock):
    def __init__(self, key_length: int):
        super().__init__(key_length)

    def encrypt(self, text, key):
        """
           Encrypt a plaintext using XTEA algorithm.
           plaintext: 64 bits length bytes-like object.
           key: 128 bits length bytes-like object.
           Return a 64 bits length bytes object.
           """

        v0, v1 = map(uint32, unpack('>2I', text))
        k = tuple(map(uint32, unpack('>4I', key)))
        sm, delta = uint32(0), uint32(0x9E3779B9)

        for i in range(32):
            v0.value += (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (sm.value + k[sm.value & 3].value)
            sm.value += delta.value
            v1.value += (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (sm.value + k[(sm.value >> 11) & 3].value)

        return pack('>2I', v0.value, v1.value)

    def decrypt(self, text, key):
        """
        Decrypt a ciphertext using XTEA algorithm.
        ciphertext: 64 bits length bytes-like object.
        key: 128 bits length bytes-like object.
        Return a 64 bits length bytes object.
        """

        v0, v1 = map(uint32, unpack('>2I', text))
        k = tuple(map(uint32, unpack('>4I', key)))
        sm, delta = uint32(0xC6EF3720), uint32(0x9E3779B9)

        for i in range(32):
            v1.value -= (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (sm.value + k[(sm.value >> 11) & 3].value)
            sm.value -= delta.value
            v0.value -= (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (sm.value + k[sm.value & 3].value)

        return pack('>2I', v0.value, v1.value)