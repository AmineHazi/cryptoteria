# entities.py

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt
from ecdsa import (
    ECDSA_generate_keys,
    ECDSA_sign,
    ECDSA_verify
)
from rfc7748 import add
from algebra import int_to_bytes

p = 2**255 - 19

class Candidate:
    def __init__(self, candidate_id, name):
        self.candidate_id = candidate_id
        self.name = name

class Voter:
    """
    Each voter has an ECDSA key pair for signature.
    In a real scenario, the voter might not have the ElGamal private key,
    that belongs to the authority. The voter only encrypts with the authority's *public* key.
    """
    def __init__(self, voter_id):
        self.voter_id = voter_id
        # Generate ECDSA key pair (private_key, public_key)
        self.ecdsa_priv, self.ecdsa_pub = ECDSA_generate_keys()

    def sign_ballot(self, ballot_ciphertext):
        """
        Uses ECDSA to sign the entire ballot (the ciphertext).
        """
        data = serialize_ec_ciphertext(ballot_ciphertext)
        return ECDSA_sign(data, self.ecdsa_priv)

    def verify_own_signature(self, ballot_ciphertext, signature):
        """
        Verifies the signature (mainly a check function). Usually, 
        the authority or the system verifies the signature with self.ecdsa_pub.
        """
        data = serialize_ec_ciphertext(ballot_ciphertext)
        r, s = signature
        return ECDSA_verify(data, r, s, self.ecdsa_pub)


class ElectionAuthority:
    """
    Holds the ElGamal (EC) key pair for the election. 
    """
    def __init__(self):
        self.private_key, self.public_key = ECEG_generate_keys()

    def decrypt_point(self, R, S):
        """
        Decrypts a single (R, S) ciphertext.
        Returns the point M = S - d*R.
        """
        return ECEG_decrypt(R, S, self.private_key)


def serialize_ec_ciphertext(ciphertext):
    """
    Utility to convert the EC ciphertext list to bytes for ECDSA hashing.
    ciphertext = [ (R1, S1), (R2, S2), ..., (R5, S5) ]
      - R1 = (Rx1, Ry1)
      - S1 = (Sx1, Sy1)
    """
    data = b""
    for (R, S) in ciphertext:
        Rx, Ry = R
        Sx, Sy = S
        data += Rx.to_bytes(32, 'big')
        data += Ry.to_bytes(32, 'big')
        data += Sx.to_bytes(32, 'big')
        data += Sy.to_bytes(32, 'big')
    return data
