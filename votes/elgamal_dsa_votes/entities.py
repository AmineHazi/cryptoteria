# entities_elgamal_dsa.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from elgamal import EG_generate_keys, EGA_encrypt, EG_decrypt, PARAM_P, PARAM_G, bruteLog
from dsa import DSA_generate_keys, DSA_sign, DSA_verify
from algebra import int_to_bytes

class Candidate:
    def __init__(self, cid, name):
        self.candidate_id = cid
        self.name = name

class Voter:
    """
    Each voter holds a DSA key pair for signing,
    but uses the Authority's ElGamal public key to encrypt.
    """
    def __init__(self, voter_id):
        self.voter_id = voter_id
        self.dsa_priv, self.dsa_pub = DSA_generate_keys()

    def sign_ballot(self, ballot_ciphertext):
        """
        Sign the entire ciphertext (list of (c1, c2)) with DSA.
        """
        data = self._serialize_ciphertext(ballot_ciphertext)
        r, s = DSA_sign(data, self.dsa_priv)
        return (r, s)

    def _serialize_ciphertext(self, ct):
        """
        Convert ciphertext = [(c1_1, c2_1), (c1_2, c2_2), ...] to bytes.
        """
        data = b""
        for (c1, c2) in ct:
            data += c1.to_bytes((c1.bit_length()+7)//8, 'big')
            data += c2.to_bytes((c2.bit_length()+7)//8, 'big')
        return data

class ElectionAuthority:
    """
    Has a classic ElGamal key pair (private, public).
    """
    def __init__(self):
        self.priv, self.pub = EG_generate_keys(PARAM_P, PARAM_G)

    def decrypt(self, c1, c2):
        """
        Decrypt a single (c1, c2) pair.
        Returns g^m mod p (in additive version).
        """
        return EG_decrypt(c1, c2, self.priv, PARAM_P)

def serialize_ciphertext(ct):
    """
    Utility for verifying signatures: same as in Voter but accessible externally.
    """
    data = b""
    for (c1, c2) in ct:
        data += c1.to_bytes((c1.bit_length()+7)//8, 'big')
        data += c2.to_bytes((c2.bit_length()+7)//8, 'big')
    return data

def verify_ballot_dsa(ciphertext, signature, dsa_pub):
    data = serialize_ciphertext(ciphertext)
    (r, s) = signature
    return DSA_verify(data, r, s, dsa_pub)
