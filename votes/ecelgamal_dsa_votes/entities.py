# entities_ecelgamal_dsa.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt
from dsa import DSA_generate_keys, DSA_sign, DSA_verify
from rfc7748 import add
from algebra import int_to_bytes

p = 2**255 - 19

class Candidate:
    def __init__(self, cid, name):
        self.candidate_id = cid
        self.name = name

class Voter:
    """
    Voter has a DSA key pair. 
    The encryption is done with the authority's *EC ElGamal* public key.
    """
    def __init__(self, voter_id):
        self.voter_id = voter_id
        self.dsa_priv, self.dsa_pub = DSA_generate_keys()

    def sign_ballot(self, ec_ciphertext):
        data = self._serialize_ec_cipher(ec_ciphertext)
        r, s = DSA_sign(data, self.dsa_priv)
        return (r, s)

    def _serialize_ec_cipher(self, ciphertext):
        """
        ciphertext = [((Rx,Ry),(Sx,Sy)), ...]
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

class ElectionAuthority:
    """
    Has an EC ElGamal key pair.
    """
    def __init__(self):
        self.priv, self.pub = ECEG_generate_keys()

    def decrypt_point(self, R, S):
        return ECEG_decrypt(R, S, self.priv)

def serialize_ec_cipher(ciphertext):
    data = b""
    for (R, S) in ciphertext:
        Rx, Ry = R
        Sx, Sy = S
        data += Rx.to_bytes(32, 'big')
        data += Ry.to_bytes(32, 'big')
        data += Sx.to_bytes(32, 'big')
        data += Sy.to_bytes(32, 'big')
    return data

def verify_ballot_dsa(ciphertext, signature, dsa_pub):
    from dsa import DSA_verify
    data = serialize_ec_cipher(ciphertext)
    (r, s) = signature
    return DSA_verify(data, r, s, dsa_pub)
