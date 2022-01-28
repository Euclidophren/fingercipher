class BaseBlock:
    def __init__(self, key_length: int, key):
        self.key_length = key_length
        self.key = key

    def encrypt(self, *args):
        pass

    def decrypt(self, *args):
        pass
