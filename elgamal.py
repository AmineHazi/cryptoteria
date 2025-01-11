from algebra import mod_inv, int_to_bytes
from random import randint

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

def bruteLog(g, c, p):
    """
    Brute force algorithm to find the discrete logarithm.
    
    Args:
        g (int): Base of the logarithm.
        c (int): Result of the exponentiation.
        p (int): Modulus.
    
    Returns:
        int: The exponent if found, otherwise -1.
    """
    s = 1
    for i in range(p):
        if s == c:
            return i
        s = (s * g) % p
        if s == c:
            return i + 1
    return -1

def EG_generate_keys(p, g):
    """
    Generate ElGamal public and private keys.
    
    Args:
        p (int): Prime modulus.
        g (int): Generator.
    
    Returns:
        tuple: Private key (int) and public key (int).
    """
    x = randint(1, p - 1)  # Private key
    y = pow(g, x, p)  # Public key
    return x, y

def EGM_encrypt(message, publickey, p, g):
    """
    Encrypt a message using multiplicative ElGamal encryption.
    
    Args:
        message (int): The message to encrypt.
        publickey (int): The recipient's public key.
        p (int): Prime modulus.
        g (int): Generator.
    
    Returns:
        tuple: Encrypted message components (c1, c2).
    """
    k = randint(0, p - 1)
    c1 = pow(g, k, p)
    c2 = (message * pow(publickey, k, p)) % p
    return c1, c2

def EGA_encrypt(message, publickey, p, g):
    """
    Encrypt a message using additive ElGamal encryption.
    
    Args:
        message (int): The message to encrypt.
        publickey (int): The recipient's public key.
        p (int): Prime modulus.
        g (int): Generator.
    
    Returns:
        tuple: Encrypted message components (c1, c2).
    """
    k = randint(0, p - 1)
    c1 = pow(g, k, p)
    c2 = (pow(g, message, p) * pow(publickey, k, p)) % p
    return c1, c2

def EG_decrypt(c1, c2, privatekey, p):
    """
    Decrypt an ElGamal encrypted message.
    
    Args:
        c1 (int): First component of the encrypted message.
        c2 (int): Second component of the encrypted message.
        privatekey (int): The recipient's private key.
        p (int): Prime modulus.
    
    Returns:
        int: The decrypted message.
    """
    s = pow(c1, privatekey, p)
    s_inv = mod_inv(s, p)
    m = (c2 * s_inv) % p
    return m

# Test Example
if __name__ == '__main__':
    p, g = PARAM_P, PARAM_G
    x, y = EG_generate_keys(p, g)

    message = 8
    print("Original message:", message)

    # Multiplicative Encryption
    c1, c2 = EGM_encrypt(message, y, p, g)
    print("Decrypted message (M):", EG_decrypt(c1, c2, x, p))

    # Additive Encryption
    c1, c2 = EGA_encrypt(message, y, p, g)
    print("Decrypted message (A):", EG_decrypt(c1, c2, x, p))
