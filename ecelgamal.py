from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint
from algebra import bruteLog

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message):
    if message == 0:
        return (1,0)
    if message == 1:
        return (BaseU, BaseV)

# Generate EC ElGamal keys
def ECEG_generate_keys():
    private_key = randint(1, ORDER - 1)
    public_key = mult(private_key, BaseU, BaseV, p)
    return private_key, public_key

# EC ElGamal Encryption
def ECEG_encrypt(message, public_key):
    M = EGencode(message)
    k = randint(1, ORDER - 1)
    R = mult(k, BaseU, BaseV, p)
    S = add(M[0], M[1], *mult(k, public_key[0], public_key[1], p), p)
    return R, S

# EC ElGamal Decryption
def ECEG_decrypt(R, S, private_key):
    # Compute shared secret
    shared_secret = mult(private_key, R[0], R[1], p)
    # Subtract the shared secret from S
    M = sub(S[0], S[1], shared_secret[0], shared_secret[1], p)

    # Decode the message (brute force search)
    if M == (1, 0):
        return 0
    elif M == (BaseU, BaseV):
        return 1
    else:
        raise ValueError("Decryption failed")
