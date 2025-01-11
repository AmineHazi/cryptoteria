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
    """
    Hashes the input message using SHA256.

    Args:
        message (bytes): The message to hash.

    Returns:
        int: The hash of the message as an integer.
    """
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)

# Generate ECDSA keys
def ECDSA_generate_keys():
    """
    Generates a pair of ECDSA keys.

    Returns:
        tuple: A tuple containing the private key (int) and the public key (tuple of ints).
    """
    private_key = randint(1, ORDER - 1)
    public_key = mult(private_key, BaseU, BaseV, p)
    return private_key, public_key

# Generate nonce
def ECDSA_generate_nonce():
    """
    Generates a nonce for ECDSA.

    Returns:
        int: A random nonce.
    """
    return randint(1, ORDER - 1)

# Generate ECDSA signature
def ECDSA_sign(message, private_key):
    """
    Generates an ECDSA signature for a given message.

    Args:
        message (bytes): The message to sign.
        private_key (int): The private key to sign the message with.

    Returns:
        tuple: A tuple containing the signature components r and s (both ints).
    """
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
    """
    Verifies an ECDSA signature.

    Args:
        message (bytes): The signed message.
        r (int): The r component of the signature.
        s (int): The s component of the signature.
        public_key (tuple): The public key corresponding to the private key that signed the message.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
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
