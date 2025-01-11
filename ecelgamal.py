from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint
from algebra import bruteLog

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    """
    Brute force method to find the discrete logarithm on the elliptic curve.

    Args:
        C1 (int): x-coordinate of the point.
        C2 (int): y-coordinate of the point.
        p (int): Prime number defining the field.

    Returns:
        int: The discrete logarithm if found, otherwise -1.
    """
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message):
    """
    Encode a message as a point on the elliptic curve.

    Args:
        message (int): The message to encode (0 or 1).

    Returns:
        tuple: The encoded point (x, y).
    """
    if message == 0:
        return (1, 0)
    if message == 1:
        return (BaseU, BaseV)

def ECEG_generate_keys():
    """
    Generate EC ElGamal key pair.

    Returns:
        tuple: The private key and the public key (x, y).
    """
    private_key = randint(1, ORDER - 1)
    public_key = mult(private_key, BaseU, BaseV, p)
    return private_key, public_key

def ECEG_encrypt(message, public_key):
    """
    Encrypt a message using EC ElGamal encryption.

    Args:
        message (int): The message to encrypt (0 or 1).
        public_key (tuple): The public key (x, y).

    Returns:
        tuple: The ciphertext (R, S) where R and S are points on the curve.
    """
    M = EGencode(message)
    k = randint(1, ORDER - 1)
    R = mult(k, BaseU, BaseV, p)
    S = add(M[0], M[1], *mult(k, public_key[0], public_key[1], p), p)
    return R, S

def ECEG_decrypt(R, S, private_key):
    """
    Decrypt a ciphertext using EC ElGamal decryption.

    Args:
        R (tuple): The point R from the ciphertext.
        S (tuple): The point S from the ciphertext.
        private_key (int): The private key.

    Returns:
        tuple: The decrypted point (x, y).
    """
    shared_secret = mult(private_key, R[0], R[1], p)
    M = sub(S[0], S[1], shared_secret[0], shared_secret[1], p)
    return M   # Return the point
