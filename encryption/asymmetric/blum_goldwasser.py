import random
import numpy
import os
import sys


#function for checking if a number is prime
def is_prime_number(x):
    if x >= 2:
        for y in range(2,x):
            if not ( x % y ):
                return False
    else:
	    return False
    return True

#function for XORing two strings
def XOR(a,b):
    a,b = str(a),str(b)
    assert(len(a) <= len(b))
    result = ""
    for i in range(len(a)):
        result += str(int(a[i]) ^ int(b[i]))
    return result

#function for finding the modular inverse
def modInverse(a, m) :
    a = a % m
    for x in range(1, m) :
        if ((a * x) % m == 1) :
            return x
    return 1

#given to us
p=499
q=547
a=-57
b=52
X0 =159201
m = 10011100000100001100

#making sure p and q are congruent to
assert(is_prime_number(p))
assert(is_prime_number(q))

assert(p % 4 == 3)
assert(q % 4 == 3)

#######################################################
###########         Key Generation          ###########
#######################################################

#creating N
N = p * q
print("N =", N)

split_string_m = str(m)

#######################################################
###########            Encryption           ###########
#######################################################

X = []
X.append(X0)


b = ""
L = len(split_string_m)
for i in range(L):
    string_x = bin(X[-1])[2:]
    size = len(string_x)
    b_i = string_x[size-1]
    b = b_i + b
    new_x = (X[i] ** 2) % N
    X.append(new_x)

print("m =", m)
print("b =", b)
str_m = str(m)

ciphertext = XOR(str_m, b)
print("C =", ciphertext)

XL = X[-1]
X0 = X[0]
XL_check = pow(X0,pow(2,L),N)
assert (XL == XL_check)


#this tuple represents what is being sent to Alice
sent_message = (ciphertext, XL)

y = sent_message[1]

#######################################################
###########            Decryption           ###########
#######################################################

firstExponent = (((p+1)//4)**L) % (p-1)
firstPhrase = "({}^{}) mod {}".format(y,firstExponent,p)
r_p = pow(y,firstExponent,p)

secondExponent = (((q+1)//4)**L) % (q-1)
secondPhrase = "({}^{}) mod {}".format(y,secondExponent,q)
r_q = pow(y,secondExponent,q)

NEWX0 = (q*modInverse(q,p)*r_p + p*modInverse(p,q)*r_q)%N
NEWX = []
NEWX.append(NEWX0)


b = ""
for i in range(L):
    string_x = bin(NEWX[-1])[2:]
    size = len(string_x)
    b_i = string_x[size-1]
    b = b_i + b
    new_x = (NEWX[i] ** 2) % N
    NEWX.append(new_x)

plaintext = XOR(ciphertext,b)
print("Plaintext  =", plaintext)
print("Message m  =", m)

#checking decrypted ciphertext is the same as the original plaintext
assert(str(m) == str(plaintext))