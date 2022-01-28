import secrets

from encryption.block.base_block import BaseBlock


class ThreeFish(BaseBlock):
    def __init__(self, key_length: int, key):
        super().__init__(key_length, key)
        # Available sizes in bits for a block
        self.VALID_BLOCK_SIZES = [256, 512, 1024]

        # Available block cipher modes
        self.VALID_BLOCK_CIPHER_MODES = ["ECB", "CBC"]

        # Size of a word in bits
        self.WORD_SIZE = 64

        self.NUMBER_ROUNDS = 76
        self.NUMBER_ROUND_KEYS = 20

        # Constant for ThreeFish (AES encryption of the plaintext "240")
        self.KEY_SCHEDULE_CONSTANT = 0x1bd11bdaa9fc1a22

        # Rotational constants for blocks composed of 4 words
        self.ROTATIONAL_CONSTANTS_4 = [
            [14, 16], [52, 57], [23, 40], [5, 37],
            [25, 33], [46, 12], [58, 22], [32, 32]
        ]

        # Rotational constants for blocks composed of 8 words
        self.ROTATIONAL_CONSTANTS_8 = [
            [46, 36, 19, 37], [33, 27, 14, 42],
            [17, 49, 36, 39], [44, 9, 54, 56],
            [39, 30, 34, 24], [13, 50, 10, 17],
            [25, 29, 39, 43], [8, 35, 56, 22]
        ]

        # Rotational constants for blocks composed of 16 words
        self.ROTATIONAL_CONSTANTS_16 = [
            [24, 13, 8, 47, 8, 17, 22, 37],
            [38, 19, 10, 55, 49, 18, 23, 52],
            [33, 4, 51, 13, 34, 41, 59, 17],
            [5, 20, 48, 41, 47, 28, 16, 25],
            [41, 9, 37, 31, 12, 47, 44, 30],
            [16, 34, 56, 51, 4, 53, 42, 41],
            [31, 44, 47, 46, 19, 42, 44, 25],
            [9, 48, 35, 52, 23, 31, 37, 20]
        ]

    def encrypt_threeFish(self, file_path, output_file_path, key, block_cipher_mode):
        block_size = len(key)

        with open(file_path, "rb") as infile, open(output_file_path, "wb") as outfile:
            # CBC mode initialization vector
            if block_cipher_mode == self.VALID_BLOCK_CIPHER_MODES[1]:
                previous_chunk = secrets.token_bytes(block_size)
                outfile.write(previous_chunk)

            while True:
                chunk = infile.read(block_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % block_size != 0:
                    chunk += bytearray(block_size - len(chunk))

                if block_cipher_mode == self.VALID_BLOCK_CIPHER_MODES[1]:
                    # bytes are converted to integer to perform XOR
                    chunk = (int.from_bytes(chunk, byteorder="big") ^ int.from_bytes(previous_chunk,
                                                                                     byteorder="big")) \
                        .to_bytes(block_size, byteorder="big")
                    previous_chunk = self.encrypt_threeFish_block(key, chunk)
                    outfile.write(previous_chunk)
                else:
                    outfile.write(self.encrypt_threeFish_block(key, chunk))


    def decrypt_threeFish(self, file_path, output_file_path, key, block_cipher_mode):
        block_size = len(key)

        with open(file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
            # CBC mode
            if block_cipher_mode == self.VALID_BLOCK_CIPHER_MODES[1]:
                previous_chunk = infile.read(block_size)

            while True:
                chunk = infile.read(block_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % block_size != 0:
                    chunk += bytearray(block_size - len(chunk))

                if block_cipher_mode == self.VALID_BLOCK_CIPHER_MODES[1]:
                    decrypted_chunk = self.decrypt_threeFish_block(key, chunk)
                    # bytes are converted to integer to perform XOR
                    outfile.write((int.from_bytes(decrypted_chunk, byteorder="big") ^
                                   int.from_bytes(previous_chunk, byteorder="big")).to_bytes(block_size,
                                                                                             byteorder="big"))
                    previous_chunk = chunk
                else:
                    outfile.write(self.decrypt_threeFish_block(key, chunk))


    def encrypt_threeFish_block(self, key, block):
        if len(key) != len(block):
            return

        word_bytes = int(self.WORD_SIZE / 8)
        round_keys = self.generate_round_keys(key)
        # split the block in words of the size word_bytes
        split_block = [int.from_bytes(block[i: i + word_bytes], byteorder="big") for i in
                       range(0, len(block), word_bytes)]
        number_words = len(split_block)
        rotational_constants = self.get_rotational_constants(number_words)

        encrypted_block = split_block
        for round_number in range(self.NUMBER_ROUNDS):
            if round_number % 4 == 0:
                encrypted_block = [((round_keys[round_number // 4][i] + encrypted_block[i]) % 2 ** self.WORD_SIZE) for i
                                   in
                                   range(number_words)]
            for i in range(0, number_words, 2):
                peer_number = int(i / 2)
                mix_result = self.mix(encrypted_block[i], encrypted_block[i + 1],
                                 rotational_constants[round_number % 8][peer_number])
                encrypted_block[i] = mix_result[0]
                encrypted_block[i + 1] = mix_result[1]
            encrypted_block = self.permute(encrypted_block)

        encrypted_block = [((round_keys[self.NUMBER_ROUNDS // 4][i] + encrypted_block[i]) % 2 ** self.WORD_SIZE) for i
                           in
                           range(number_words)]

        return b"".join([encrypted_block[i].to_bytes(8, byteorder="big") for i in range(number_words)])

    def decrypt_threeFish_block(self, key, block):
        if len(key) != len(block):
            return

        word_bytes = int(self.WORD_SIZE / 8)
        round_keys = self.generate_round_keys(key)
        # split the block in words of the size word_bytes
        split_block = [int.from_bytes(block[i: i + word_bytes], byteorder="big") for i in
                       range(0, len(block), word_bytes)]
        number_words = len(split_block)
        rotational_constants = self.get_rotational_constants(number_words)

        decrypted_block = [((split_block[i] - round_keys[self.NUMBER_ROUNDS // 4][i]) % 2 ** WORD_SIZE) for i in
                           range(number_words)]
        for round_number in range(self.NUMBER_ROUNDS - 1, -1, -1):
            decrypted_block = self.inv_permute(decrypted_block)
            for i in range(0, number_words, 2):
                peer_number = int(i / 2)
                mix_result = self.inv_mix(decrypted_block[i], decrypted_block[i + 1],
                                     rotational_constants[round_number % 8][peer_number])
                decrypted_block[i] = mix_result[0]
                decrypted_block[i + 1] = mix_result[1]
            if round_number % 4 == 0:
                decrypted_block = [((decrypted_block[i] - round_keys[round_number // 4][i]) % 2 ** self.WORD_SIZE) for i in
                                   range(number_words)]

        return b"".join([decrypted_block[i].to_bytes(8, byteorder="big") for i in range(number_words)])

    def generate_round_keys(self, key):
        tweak0 = 0x7372742032303137
        tweak1 = 0x7574742067733135
        tweak2 = tweak0 ^ tweak1
        tweaks = [tweak0, tweak1, tweak2]

        word_bytes = int(self.WORD_SIZE / 8)

        split_key = [int.from_bytes(key[i: i + word_bytes], byteorder="big") for i in range(0, len(key), word_bytes)]
        key_n = self.KEY_SCHEDULE_CONSTANT
        for i in range(len(split_key)):
            key_n = key_n ^ split_key[i]
        split_key.append(key_n)

        round_keys = []
        for i in range(self.NUMBER_ROUND_KEYS):
            ki = []
            j = 0
            while j <= len(split_key) - 5:
                ki.append(split_key[(i + j) % len(split_key)])
                j += 1

            ki.append((split_key[(i + j) % len(split_key)] + tweaks[i % 3]) % 2 ** self.WORD_SIZE)
            j += 1
            ki.append((split_key[(i + j) % len(split_key)] + tweaks[(i + 1) % 3]) % 2 ** self.WORD_SIZE)
            j += 1
            ki.append((split_key[(i + j) % len(split_key)] + i) % 2 ** self.WORD_SIZE)
            round_keys.append(ki)

        return round_keys

    def get_rotational_constants(self, number_words):
        if number_words == 4:
            return self.ROTATIONAL_CONSTANTS_4
        elif number_words == 8:
            return self.ROTATIONAL_CONSTANTS_8
        elif number_words == 16:
            return self.ROTATIONAL_CONSTANTS_16
        else:
            return

    def mix(self, word1, word2, rotational_constant):
        word1_result = (word1 + word2) % 2 ** self.WORD_SIZE
        word2 = word1_result ^ (
                (word2 << rotational_constant) & (2 ** self.WORD_SIZE - 1) | word2 >> (self.WORD_SIZE - rotational_constant))
        return word1_result, word2

    def inv_mix(self, word1, word2, rotational_constant):
        word2_result = (word2 ^ word1) >> rotational_constant | (
                (word2 ^ word1) << (self.WORD_SIZE - rotational_constant) & (2 ** self.WORD_SIZE - 1))
        word1 = (word1 - word2_result) % 2 ** self.WORD_SIZE
        return word1, word2_result

    def permute(self, encrypted_block):
        # 1 2 3 4 => 3 2 4 1
        for i in range(0, len(encrypted_block), 4):
            word0 = encrypted_block[i]
            encrypted_block[i] = encrypted_block[i + 2]
            encrypted_block[i + 2] = encrypted_block[i + 3]
            encrypted_block[i + 3] = word0
        return encrypted_block

    def inv_permute(self, encrypted_block):
        # 1 2 3 4 => 4 2 1 3
        for i in range(0, len(encrypted_block), 4):
            word0 = encrypted_block[i]
            encrypted_block[i] = encrypted_block[i + 3]
            encrypted_block[i + 3] = encrypted_block[i + 2]
            encrypted_block[i + 2] = word0
        return encrypted_block
