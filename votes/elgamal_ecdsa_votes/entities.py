# entities_elgamal_ecdsa.py

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from elgamal import EG_generate_keys, EGA_encrypt, EG_decrypt, PARAM_P, PARAM_G, bruteLog
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify

class Candidate:
    def __init__(self, cid, name):
        self.candidate_id = cid
        self.name = name

class Voter:
    """
    Voter uses an ECDSA key pair to sign,
    but uses the election authority's classic ElGamal public key to encrypt.
    """
    def __init__(self, voter_id):
        self.voter_id = voter_id
        self.ecdsa_priv, self.ecdsa_pub = ECDSA_generate_keys()

    def sign_ballot(self, ballot_cipher):
        data = self._serialize_cipher(ballot_cipher)
        return ECDSA_sign(data, self.ecdsa_priv)

    def _serialize_cipher(self, ballot_cipher):
        data = b""
        for (c1, c2) in ballot_cipher:
            data += c1.to_bytes((c1.bit_length()+7)//8, 'big')
            data += c2.to_bytes((c2.bit_length()+7)//8, 'big')
        return data

class ElectionAuthority:
    def __init__(self):
        self.priv, self.pub = EG_generate_keys(PARAM_P, PARAM_G)

    def decrypt(self, c1, c2):
        return EG_decrypt(c1, c2, self.priv, PARAM_P)

def serialize_cipher_elgamal(ciphertext):
    data = b""
    for (c1, c2) in ciphertext:
        data += c1.to_bytes((c1.bit_length()+7)//8, 'big')
        data += c2.to_bytes((c2.bit_length()+7)//8, 'big')
    return data

def verify_ballot_ecdsa(ciphertext, signature, pub):
    from ecdsa import ECDSA_verify
    data = serialize_cipher_elgamal(ciphertext)
    (r, s) = signature
    return ECDSA_verify(data, r, s, pub)
