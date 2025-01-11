from algebra import mod_inv
from Crypto.Hash import SHA256
from random import randint

# Parameters from MODP Group 24 (RFC 5114)
PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597
PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3
PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

# Hash function
def H(message):
    """
    Hashes the input message using SHA256.

    Args:
        message (bytes): The message to be hashed.

    Returns:
        int: The integer representation of the hash.
    """
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)

# Generate DSA keys
def DSA_generate_keys():
    """
    Generates a pair of DSA keys.

    Returns:
        tuple: A tuple containing the private key (x) and the public key (y).
    """
    x = randint(1, PARAM_Q - 1)  # Private key
    y = pow(PARAM_G, x, PARAM_P)  # Public key
    return x, y

# Generate nonce
def DSA_generate_nonce():
    """
    Generates a nonce for DSA.

    Returns:
        int: A random nonce.
    """
    return randint(1, PARAM_Q - 1)

# Generate DSA signature
def DSA_sign(message, x):
    """
    Generates a DSA signature for the given message.

    Args:
        message (bytes): The message to be signed.
        x (int): The private key.

    Returns:
        tuple: A tuple containing the signature components (r, s).
    """
    k = DSA_generate_nonce()
    r = pow(PARAM_G, k, PARAM_P) % PARAM_Q
    if r == 0:
        return DSA_sign(message, x)

    k_inv = mod_inv(k, PARAM_Q)
    hash_val = H(message)
    s = (k_inv * (hash_val + x * r)) % PARAM_Q
    if s == 0:
        return DSA_sign(message, x)

    return r, s

# Verify DSA signature
def DSA_verify(message, r, s, y):
    """
    Verifies a DSA signature.

    Args:
        message (bytes): The signed message.
        r (int): The first component of the signature.
        s (int): The second component of the signature.
        y (int): The public key.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    if not (0 < r < PARAM_Q and 0 < s < PARAM_Q):
        return False

    w = mod_inv(s, PARAM_Q)
    hash_val = H(message)
    u1 = (hash_val * w) % PARAM_Q
    u2 = (r * w) % PARAM_Q

    v = ((pow(PARAM_G, u1, PARAM_P) * pow(y, u2, PARAM_P)) % PARAM_P) % PARAM_Q

    return v == r

# Test Example
if __name__ == '__main__':
    message = b"An important message !"
    x, y = DSA_generate_keys()
    r, s = DSA_sign(message, x)
    print("Signature valid:", DSA_verify(message, r, s, y))
