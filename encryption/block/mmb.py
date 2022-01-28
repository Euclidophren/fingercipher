from builtins import int

from encryption.block.base_block import BaseBlock


class MMB(BaseBlock):
    def __init__(self, key_length: int, key):
        super().__init__(key_length, key)
        self.delta = 0x2AAAAAAA
        self.G = [0x25F1CDB, 0x4BE39B6, 0x12F8E6D8, 0x2F8E6D81]
        self.G_inv = [0xDAD4694, 0x06D6A34A, 0x81B5A8D2, 0x281B5A8D]

    def teta(self, x):
        y = [0] * 4
        y[0] = x[0] ^ x[1] ^ x[3]
        y[1] = x[0] ^ x[1] ^ x[2]
        y[2] = x[1] ^ x[2] ^ x[3]
        y[3] = x[0] ^ x[2] ^ x[3]
        for i in range(4):
            x[i] = y[i]
        return x

    def eta(self, x):
        x[0] = x[0] ^ ((1 & x[0]) * self.delta)
        x[3] = x[3] ^ ((1 & x[3]) * self.delta)
        return x

    def gamma(self, x):
        y = [0] * 4
        for i in range(4):
            if x[i] == 0xFFFFFFFF:
                y[i] = x[i]
            else:
                temp = x[i] * self.G[i]
                y[i] = temp % 0xFFFFFFFF
        for i in range(4):
            x[i] = y[i]

    def gamma_inv(self, x):
        y = [0] * 4
        for i in range(4):
            if x[i] == 0xFFFFFFFF:
                y[i] = x[i]
            else:
                temp = x[i] * self.G_inv[i]
                y[i] = temp % 0xFFFFFFFF
        for i in range(4):
            x[i] = y[i]

        return x

    def sigma(self, x, k, J):
        y = [0] * 4
        for i in range(4):
            k_iJ = k[(i + J) % 4]
            y[i] = x[i] ^ k_iJ
        for i in range(4):
            x[i] = y[i]
        return x

    def rho(self, x, k, J):
        x = self.sigma(x, k, J)
        x = self.gamma(x)
        x = self.eta(x)
        x = self.teta(x)
        return x

    def rho_inv(self, x, k, J):
        x = self.teta(x)
        x = self.eta(x)
        x = self.gamma_inv(x)
        x = self.sigma(x, k, J)
        return x

    def encrypt(self, x, k, y):
        for i in range(4):
            y[i] = x[i]
        for i in range(6):
            x = self.rho(y, k, i)
        x = self.sigma(y, k, 6)
        return x

    def decrypt(self, x, k, y):
        for i in range(4):
            y[i] = x[i]
        x = self.sigma(y, k, 6)
        for i in range(6):
            x = self.rho_inv(y, k, i)
        return x
