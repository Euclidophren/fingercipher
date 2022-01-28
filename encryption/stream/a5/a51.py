import re
import copy

from encryption.stream.base_stream import BaseStream

reg_x_length = 19
reg_y_length = 22
reg_z_length = 23

key_one = ""
reg_x = []
reg_y = []
reg_z = []


def loading_registers(key):  # loads registers using a 64-bit key as a parameter
    i = 0
    while i < reg_x_length:
        reg_x.insert(i, int(key[i]))  # takes first 19 elements from key
        i = i + 1
    j = 0
    p = reg_x_length
    while j < reg_y_length:
        reg_y.insert(j, int(key[p]))  # takes next 22 elements from key
        p = p + 1
        j = j + 1
    k = reg_y_length + reg_x_length
    r = 0
    while r < reg_z_length:
        reg_z.insert(r, int(key[k]))  # takes next 23 elements from key
        k = k + 1
        r = r + 1


def set_key(key):
    if len(key) == 64 and re.match("^([01])+", key):
        loading_registers(key)
        return True
    return False


def get_key():  # gets the key
    return key_one


def to_binary(plain):  # converts plaintext to binary
    s = ""
    i = 0
    for i in plain:
        binary = str(' '.join(format(ord(x), 'b') for x in i))
        j = len(binary)
        while (j < 8):
            binary = "0" + binary
            s = s + binary
            j = j + 1
    binary_values = []
    k = 0
    while (k < len(s)):
        binary_values.insert(k, int(s[k]))
        k = k + 1
    return binary_values


def get_majority(x, y, z):
    if x + y + z > 1:
        return 1
    else:
        return 0


def convert_binary_to_str(binary):  # converts binary to string
    s = ""
    length = len(binary) - 8
    i = 0
    while i <= length:
        s = s + chr(int(binary[i:i + 8], 2))
        i = i + 8
    return str(s)


class A51(BaseStream):

    def __init__(self, key_length: int):

        super().__init__(key_length)

    def get_keystream(self, length):
        reg_x_temp = copy.deepcopy(reg_x)
        reg_y_temp = copy.deepcopy(reg_y)
        reg_z_temp = copy.deepcopy(reg_z)
        keystream = []
        i = 0
        while i < length:
            majority = get_majority(reg_x_temp[8], reg_y_temp[10], reg_z_temp[10])
            if reg_x_temp[8] == majority:
                new = reg_x_temp[13] ^ reg_x_temp[16] ^ reg_x_temp[17] ^ reg_x_temp[18]
                reg_x_temp_two = copy.deepcopy(reg_x_temp)
                j = 1
                while j < len(reg_x_temp):
                    reg_x_temp[j] = reg_x_temp_two[j - 1]
                    j = j + 1
                reg_x_temp[0] = new

            if reg_y_temp[10] == majority:
                new_one = reg_y_temp[20] ^ reg_y_temp[21]
                reg_y_temp_two = copy.deepcopy(reg_y_temp)
                k = 1
                while k < len(reg_y_temp):
                    reg_y_temp[k] = reg_y_temp_two[k - 1]
                    k = k + 1
                reg_y_temp[0] = new_one

            if reg_z_temp[10] == majority:
                new_two = reg_z_temp[7] ^ reg_z_temp[20] ^ reg_z_temp[21] ^ reg_z_temp[22]
                reg_z_temp_two = copy.deepcopy(reg_z_temp)
                m = 1
                while m < len(reg_z_temp):
                    reg_z_temp[m] = reg_z_temp_two[m - 1]
                    m = m + 1
                reg_z_temp[0] = new_two

            keystream.insert(i, reg_x_temp[18] ^ reg_y_temp[21] ^ reg_z_temp[22])
            i = i + 1
        return keystream

    def encrypt(self, plain):
        binary = to_binary(plain)
        keystream = self.get_keystream(len(binary))
        i = 0
        while i < len(binary):
            s = s + str(binary[i] ^ keystream[i])
            i = i + 1
        return s

    def decrypt(self, cipher):
        s = ""
        binary = []
        keystream = self.get_keystream(len(cipher))
        i = 0
        while i < len(cipher):
            binary.insert(i, int(cipher[i]))
            s = s + str(binary[i] ^ keystream[i])
            i = i + 1
        return convert_binary_to_str(str(s))
