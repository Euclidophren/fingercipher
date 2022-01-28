import base64


class SchmidtSamoa:
    def encrypt(self, message, pk):
        return base64.b64encode(''.join([str(int(pow(ord(char), pk, pk))) + " " for char in message]).strip().encode())

    def decrypt(self, cipher, sk, n):
        return ''.join([str(chr(pow(int(num), sk, n))) for num in base64.b64decode(cipher).split(" ")])