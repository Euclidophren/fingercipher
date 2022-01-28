from encryption.block import BaseBlock

NUM_ROUNDS = {
    (32, 64): 22,
    (48, 72): 22,
    (48, 96): 23,
    (64, 96): 26,
    (64, 128): 27,
    (96, 96): 28,
    (96, 144): 29,
    (128, 128): 32,
    (128, 192): 33,
    (128, 256): 34,
}


class SPECK(BaseBlock):
    def __init__(self, block_size, key_size, key_length: int, key, master_key=None):
        super().__init__(key_length, key)
        assert (block_size, key_size) in NUM_ROUNDS
        self.block_size = block_size
        self.key_size = key_size
        self.__num_rounds = NUM_ROUNDS[(block_size, key_size)]
        if block_size == 32 and key_size == 64:
            self.__alpha = 7
            self.__beta = 2
        else:
            self.__alpha = 8
            self.__beta = 3
        self.__dim = block_size / 2
        self.__mod = 1 << self.__dim
        if master_key is not None:
            self.change_key(master_key)

    def __rshift(self, x, i):
        assert i in (self.__alpha, self.__beta)
        return ((x << (self.__dim - i)) % self.__mod) | (x >> i)

    def __lshift(self, x, i):
        assert i in (self.__alpha, self.__beta)
        return ((x << i) % self.__mod) | (x >> (self.__dim - i))

    def __first_feistel(self, x, y):
        return y, (self.__rshift(x, self.__alpha) + y) % self.__mod

    def __second_feistel(self, x, y):
        return y, self.__lshift(x, self.__beta) ^ y

    def __first_feistel_inv(self, x, y):
        return self.__lshift((y - x) % self.__mod, self.__alpha), x

    def __second_feistel_inv(self, x, y):
        return self.__rshift(x ^ y, self.__beta), x

    def change_key(self, master_key):
        assert 0 <= master_key < (1 << self.key_size)
        self.__round_key = [master_key % self.__mod]
        master_key >>= self.__dim
        llist = []
        for i in range(self.key_size / self.__dim - 1):
            llist.append(master_key % self.__mod)
            master_key >>= self.__dim
        for i in range(self.__num_rounds - 1):
            l, r = self.__first_feistel(llist[i], self.__round_key[i])
            r ^= i
            l, r = self.__second_feistel(l, r)
            llist.append(l)
            self.__round_key.append(r)

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << self.block_size)
        l = plaintext >> self.__dim
        r = plaintext % self.__mod
        for i in range(self.__num_rounds):
            l, r = self.__first_feistel(l, r)
            r ^= self.__round_key[i]
            l, r = self.__second_feistel(l, r)
        ciphertext = (l << self.__dim) | r
        assert 0 <= ciphertext < (1 << self.block_size)
        return ciphertext

    def decrypt(self, ciphertext):
        assert 0 <= ciphertext < (1 << self.block_size)
        l = ciphertext >> self.__dim
        r = ciphertext % self.__mod
        for i in range(self.__num_rounds - 1, -1, -1):
            l, r = self.__second_feistel_inv(l, r)
            r ^= self.__round_key[i]
            l, r = self.__first_feistel_inv(l, r)
        plaintext = (l << self.__dim) | r
        assert 0 <= plaintext < (1 << self.block_size)
        return plaintext