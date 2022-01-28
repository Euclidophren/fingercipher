M = 0xffffffff


def add(x, y):
    return (x + y) & M


def xor(x, y):
    return x ^ y


def rol(x, s):
    return ((x << s) | (x >> (32 - s))) & M


def m8_round(L, R, ri, k, adk, aek):
    """
    One round of the algorithm.

    L, R: input
    ri: round index
    k: 256-bit execution key
    adk: 24-bit algorithm decision key
    aek: 96-bit algorithm expansion key
    """

    op = [[add, xor][(adk >> (23 - i)) & 1] for i in range(9)]
    S1 = (adk >> 10) & 0x1f
    S2 = (adk >> 5) & 0x1f
    S3 = (adk >> 0) & 0x1f
    A = (aek >> 64) & M
    B = (aek >> 32) & M
    C = (aek >> 0) & M
    KR = (k >> (32 + 64 * (3 - ri % 4))) & M
    KL = (k >> (0 + 64 * (3 - ri % 4))) & M

    x = op[0](L, KL)
    y = op[2](op[1](rol(x, S1), x), A)
    z = op[5](op[4](op[3](rol(y, S2), y), B), KR)
    return op[8](op[7](op[6](rol(z, S3), z), C), R), L


def m8_keyexpand(dk, kek, adks, aeks):
    """
    Key expansion.

    dk: 64-bit data key
    kek: 256-bit key expansion key
    adks: algorithm decision keys
    aeks: algorithm expansion keys
    """

    L = (dk >> 32) & M
    R = (dk >> 0) & M
    k = 0
    for i in range(8):
        L, R = m8_round(L, R, i, kek, adks[i], aeks[i])
        k |= (L << (32 * (7 - i)))
    return k


def m8_encrypt(data, N, dk, kek, adks, aeks):
    """
    Encrypt one block with M8.

    data: 64-bit input block
    N: number of rounds (must be >= 8)
    dk: 64-bit data key
    kek: 256-bit key expansion key
    adks: a list of N 24-bit algorithm decision keys
    aeks: a list of N 96-bit algorithm expansion keys
    """

    ek = m8_keyexpand(dk, kek, adks, aeks)
    L = (data >> 32) & M
    R = (data >> 0) & M
    for i in range(N):
        L, R = m8_round(L, R, i, ek, adks[i], aeks[i])
    return (L << 32) | R
