#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from elgamal import (
    EG_generate_keys,       # for election authority
    EGA_encrypt,            # additive ElGamal encryption
    EG_decrypt              # ElGamal decryption
)
from dsa import (
    DSA_generate_keys, 
    DSA_sign, 
    DSA_verify
)
from algebra import int_to_bytes
from rfc7748 import add  # Not strictly needed here, but let's keep for consistency

# Parameters from elgamal.py (global)
from elgamal import PARAM_P, PARAM_G

###############################################################################
# 1. GENERATE ELECTION AUTHORITY KEY (ELGAMAL in Zp)
###############################################################################
election_priv, election_pub = EG_generate_keys(PARAM_P, PARAM_G)

###############################################################################
# 2. GENERATE VOTERS' SIGNATURE KEYS (DSA)
###############################################################################
NUM_VOTERS = 10
NUM_CANDIDATES = 5

voter_dsa_keys = []
for _ in range(NUM_VOTERS):
    x, y = DSA_generate_keys()  # x=priv, y=pub
    voter_dsa_keys.append((x, y))

###############################################################################
# 3. HELPER FUNCTIONS
###############################################################################
def encrypt_ballot_elgamal(vote):
    """
    Encrypts a ballot (5 bits) with *Additive* ElGamal:
     - EGA_encrypt(message, election_pub, p, g).
    Returns: [(c1_i, c2_i), ...] for i in [0..4].
    """
    ciphertext = []
    for bit in vote:
        # encode 'bit' as an integer (0 or 1)
        c1, c2 = EGA_encrypt(bit, election_pub, PARAM_P, PARAM_G)
        ciphertext.append((c1, c2))
    return ciphertext

def sign_ballot_dsa(ciphertext, dsa_priv):
    """
    Signs the entire ciphertext with DSA. 
    We convert the ciphertext to bytes for hashing: 
      (c1_1, c2_1, c1_2, c2_2, ...).
    """
    data = b""
    for (c1, c2) in ciphertext:
        data += c1.to_bytes((c1.bit_length()+7)//8, 'big')
        data += c2.to_bytes((c2.bit_length()+7)//8, 'big')

    r, s = DSA_sign(data, dsa_priv)
    return (r, s)

def verify_ballot_dsa(ciphertext, signature, dsa_pub):
    """
    Verifies the DSA signature on the ciphertext.
    """
    data = b""
    for (c1, c2) in ciphertext:
        data += c1.to_bytes((c1.bit_length()+7)//8, 'big')
        data += c2.to_bytes((c2.bit_length()+7)//8, 'big')

    r, s = signature
    return DSA_verify(data, r, s, dsa_pub)

def sum_encrypted_votes_elgamal(all_ciphertexts):
    """
    Homomorphically sum the additive ElGamal ciphertexts:
      EGA_Encrypt(m1) * EGA_Encrypt(m2) = EGA_Encrypt(m1 + m2).
    So we multiply (c1,c2) pairs componentwise.
    """
    num_candidates = len(all_ciphertexts[0])
    # Start accumulators with the first ballot
    c1_sum = [all_ciphertexts[0][i][0] for i in range(num_candidates)]
    c2_sum = [all_ciphertexts[0][i][1] for i in range(num_candidates)]

    for ballot in all_ciphertexts[1:]:
        for i in range(num_candidates):
            c1_sum[i] = (c1_sum[i] * ballot[i][0]) % PARAM_P
            c2_sum[i] = (c2_sum[i] * ballot[i][1]) % PARAM_P

    return list(zip(c1_sum, c2_sum))

def decrypt_and_decode_elgamal(c1c2, election_priv, max_votes):
    """
    Decrypt additive ElGamal, get g^m.
    Then brute force to find m in [0..max_votes].
    """
    from elgamal import EG_decrypt, PARAM_G, bruteLog

    c1, c2 = c1c2
    val = EG_decrypt(c1, c2, election_priv, PARAM_P)
    # val = g^m mod p.  We search m in [0..max_votes].
    m = bruteLog(PARAM_G, val, PARAM_P)
    if 0 <= m <= max_votes:
        return m
    else:
        return -1

###############################################################################
# 4. MAIN
###############################################################################
if __name__ == "__main__":
    # Each voter: 1-of-5
    votes = [
        [1,0,0,0,0],
        [0,1,0,0,0],
        [0,0,1,0,0],
        [0,0,0,1,0],
        [0,0,0,0,1],
        [1,0,0,0,0],
        [0,1,0,0,0],
        [1,0,0,0,0],
        [0,0,1,0,0],
        [0,0,0,1,0],
    ]

    # Encrypt + sign
    all_ciphertexts = []
    for i, vote in enumerate(votes):
        ciphertext = encrypt_ballot_elgamal(vote)
        sig = sign_ballot_dsa(ciphertext, voter_dsa_keys[i][0])  # dsa_priv
        # verify
        assert verify_ballot_dsa(ciphertext, sig, voter_dsa_keys[i][1]), "Invalid signature!"
        all_ciphertexts.append((ciphertext, sig))

    # Summation: only keep ballots whose signature is valid
    valid_ciphertexts = []
    for i, (ct, sig) in enumerate(all_ciphertexts):
        if verify_ballot_dsa(ct, sig, voter_dsa_keys[i][1]):
            valid_ciphertexts.append(ct)

    # Homomorphically sum
    encrypted_results = sum_encrypted_votes_elgamal(valid_ciphertexts)

    # Decrypt and decode
    final_counts = []
    for i in range(NUM_CANDIDATES):
        c1c2 = encrypted_results[i]
        m = decrypt_and_decode_elgamal(c1c2, election_priv, max_votes=NUM_VOTERS)
        final_counts.append(m)

    print("ElGamal + DSA -> Election results:", final_counts)
