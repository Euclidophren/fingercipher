from ctypes import c_uint32 as uint32
from struct import pack, unpack


from encryption.block.base_block import BaseBlock


class TEA(BaseBlock):
    def __init__(self, key_length: int):
        super().__init__(key_length)

    def encrypt(self, text, key, delta=0x9E3779B9):
        '''
        Encrypt a plaintext using TEA algorithm.
        plaintext: 64 bits length bytes-like object.
        key: 128 bits length bytes-like object.
        Return a 64 bits length bytes object.
        '''

        v0, v1 = map(uint32, unpack('>2I', text))
        k0, k1, k2, k3 = map(uint32, unpack('>4I', key))
        sm, delta = uint32(0), uint32(delta)

        for i in range(32):
            sm.value += delta.value
            v0.value += ((v1.value << 4) + k0.value) ^ (v1.value + sm.value) ^ ((v1.value >> 5) + k1.value)
            v1.value += ((v0.value << 4) + k2.value) ^ (v0.value + sm.value) ^ ((v0.value >> 5) + k3.value)

        return pack('>2I', v0.value, v1.value)

    def decrypt(self, text, key, delta=0x9E3779B9):
        """
        Decrypt a ciphertext using XTEA algorithm.
        ciphertext: 64 bits length bytes-like object.
        key: 128 bits length bytes-like object.
        Return a 64 bits length bytes object.
        """

        v0, v1 = map(uint32, unpack('>2I', text))
        k0, k1, k2, k3 = map(uint32, unpack('>4I', key))
        sm, delta = uint32(0xC6EF3720), uint32(delta)

        for i in range(32):
            v1.value -= ((v0.value << 4) + k2.value) ^ (v0.value + sm.value) ^ ((v0.value >> 5) + k3.value)
            v0.value -= ((v1.value << 4) + k0.value) ^ (v1.value + sm.value) ^ ((v1.value >> 5) + k1.value)
            sm.value -= delta.value

        return pack('>2I', v0.value, v1.value)