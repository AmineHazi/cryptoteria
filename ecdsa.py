from rfc7748 import add, mult, computeVcoordinate
from algebra import mod_inv
from Crypto.Hash import SHA256
from random import randint

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)
BaseU = 9
BaseV = computeVcoordinate(BaseU)

# Hash function
def H(message):
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)

# Generate ECDSA keys
def ECDSA_generate_keys():
    private_key = randint(1, ORDER - 1)
    public_key = mult(private_key, BaseU, BaseV, p)
    return private_key, public_key

# Generate nonce
def ECDSA_generate_nonce():
    return randint(1, ORDER - 1)

# Generate ECDSA signature
def ECDSA_sign(message, private_key):
    z = H(message) % ORDER
    k = ECDSA_generate_nonce()

    # Compute R
    Rx, Ry = mult(k, BaseU, BaseV, p)
    r = Rx % ORDER
    if r == 0:
        return ECDSA_sign(message, private_key)

    # Compute s
    k_inv = mod_inv(k, ORDER)
    s = (k_inv * (z + r * private_key)) % ORDER
    if s == 0:
        return ECDSA_sign(message, private_key)

    return r, s

# Verify ECDSA signature
def ECDSA_verify(message, r, s, public_key):
    if not (0 < r < ORDER and 0 < s < ORDER):
        return False

    z = H(message) % ORDER
    w = mod_inv(s, ORDER)
    u1 = (z * w) % ORDER
    u2 = (r * w) % ORDER

    # Compute point (x, y)
    x1, y1 = mult(u1, BaseU, BaseV, p)
    x2, y2 = mult(u2, public_key[0], public_key[1], p)
    x, y = add(x1, y1, x2, y2, p)

    # Verify r == x mod ORDER
    return (x % ORDER) == r

# Test Example
if __name__ == '__main__':
    message = b"A very very important message !"

    # Generate keys
    private_key, public_key = ECDSA_generate_keys()

    # Sign the message
    r, s = ECDSA_sign(message, private_key)
    print("Signature:", (hex(r), hex(s)))

    # Verify the signature
    valid = ECDSA_verify(message, r, s, public_key)
    print("Signature valid:", valid)
