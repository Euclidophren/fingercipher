from encryption.block.base_block import BaseBlock


class IRAQI(BaseBlock):
    def __init__(self, key_length: int, key):
        super().__init__(key_length, key)

        self.chaos1 = [
            173, 84, 240, 67, 1, 53, 254, 36, 41, 172, 115, 109, 223, 199, 152, 189, 90, 46,
            149, 193, 218, 130, 250, 40, 203, 4, 35, 237, 236, 246, 213, 143, 169, 176, 48,
            23, 61, 206, 69, 34, 97, 155, 4, 109, 183, 220, 42, 64, 21, 123, 29, 233, 253,
            105, 183, 209, 1, 191, 113, 12, 46, 7, 8, 183, 166, 199, 166, 7, 78, 37, 135,
            252, 174, 84, 140, 164, 152, 94, 22, 185, 59, 68, 181, 60, 176, 67, 51, 25, 28,
            190, 138, 198, 44, 90, 92, 221, 149, 175, 186, 25, 49, 210, 50, 237, 41, 207,
            31, 226, 114, 121, 230, 15, 58, 25, 142, 58, 98, 232, 59, 3, 189, 28, 8, 116,
            131, 185, 78, 250, 239, 33, 116, 173, 94, 45, 104, 62, 122, 179, 18, 150, 246,
            250, 17, 8, 79, 157, 225, 238, 47, 10, 133, 58, 8, 126, 82, 68, 153, 141, 2, 158,
            204, 50, 130, 53, 59, 32, 243, 160, 172, 35, 24, 107, 35, 115, 228, 143, 28,
            224, 77, 55, 25, 28, 120, 89, 186, 152, 49, 84, 117, 180, 30, 138, 134, 77, 182,
            157, 61, 230, 22, 149, 54, 15, 110, 32, 213, 155, 106, 78, 16, 23, 89, 140, 158,
            169, 96, 136, 186, 104, 30, 199, 67, 35, 218, 159, 210, 109, 28, 238, 33, 150,
            173, 180, 247, 201, 83, 150, 105, 164, 228, 59, 207, 101, 221, 99, 52, 120,
            199, 31, 6, 144, 202, 215, 209, 49, 42, 195
        ]
        self.fixed_key = [
            46, 245, 138, 13, 244, 233, 238, 154, 139, 30, 241, 90, 47, 205, 171, 97, 223,
            190, 28, 10, 185, 13, 23, 137, 30, 208, 254, 143, 165, 101, 27, 48
        ]
        self.l = [[0] * 16 for _ in range(32)]
        self.r = [[0] * 16 for _ in range(32)]

    def pbc1(self):
        chaos = [0] * 256
        for i in range(256):
            chaos[i] = self.chaos1[i] ^ self.key[i % 20]
        for w in range(4):
            round_init(self.fixed_key, 32)
            for i in range(256):
                chaos[i] = self.chaos1[i] ^ self.key[i % 32]
            for i in range(32):
                chaos[i] = ciphertext[i]

        for i in range(16):
            err = 0
            for ix in range(16):
                if rnd_perm[i][x] == ciphertext[7] % 16:
                    x = ix
                    err = 1
                    round_init(ciphertext, 4)
                if err == 0:
                    rnd_perm[i][ix] = ciphertext[7] % 16
                else:
                    err = 0
                    ix -= 1
        err = 0
        for ix in range(256):
            round_init(ciphertext, 4)
            for x in range(ix):
                if rnd_glob[x] == ciphertext[7] % 256:
                    x = ix
                    err = 1
                    round_init(ciphertext, 4)
            if err == 0:
                rnd_glob[ix] = ciphertext[7] % 256
            else:
                err = 0
                ix -= 1
        for i in range(256):
            chaos[i] = chaos[i] ^ self.key[i % 20]

        for w in range(4):
            round_init(self.fixed_key, 32)
            for i in range(256):
                chaos[i] = chaos[i] ^ ciphertext[i % 32]
            for i in range(32):
                self.fixed_key[i] = ciphertext[i]

    def round_init(self, text, round):
        for i in range(16):
            self.l[0][i] = text[i]
            self.r[0][i] = text[i + 16]

        for i in range(round):
            one_way_init(r[i - 1])
            for y in range(16):
                self.l[i][y] = r[i - 1][y]
                self.r[i][y] = self.l[i - 1][y] ^ one_way_res[y]

        for i in range(16):
            ciphertext[i] = self.l[round - 1][i]
            ciphertext[i + 16] = self.r[round - 1][i]
