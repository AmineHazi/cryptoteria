#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from elgamal import (
    EG_generate_keys,
    EGA_encrypt,
    EG_decrypt,
    PARAM_P,
    PARAM_G,
    bruteLog
)
from ecdsa import (
    ECDSA_generate_keys,
    ECDSA_sign,
    ECDSA_verify
)

###############################################################################
# For the same reason, we assume "Additive" ElGamal to handle sums homomorphically.
###############################################################################

NUM_VOTERS = 10
NUM_CANDIDATES = 5

# Election authority keys (ElGamal)
election_priv, election_pub = EG_generate_keys(PARAM_P, PARAM_G)

# Voter keys (ECDSA)
voter_ecdsa_keys = [ECDSA_generate_keys() for _ in range(NUM_VOTERS)]

def encrypt_ballot_elgamal(vote):
    """
    Encrypt using additive ElGamal: EGA_encrypt
    Returns a list of (c1, c2) pairs.
    """
    ciphertext = []
    for bit in vote:
        c1, c2 = EGA_encrypt(bit, election_pub, PARAM_P, PARAM_G)
        ciphertext.append((c1, c2))
    return ciphertext

def serialize_ciphertext(ct):
    data = b""
    for (c1, c2) in ct:
        data += c1.to_bytes((c1.bit_length()+7)//8, 'big')
        data += c2.to_bytes((c2.bit_length()+7)//8, 'big')
    return data

def sign_ballot_ecdsa(ciphertext, ecdsa_priv):
    data = serialize_ciphertext(ciphertext)
    return ECDSA_sign(data, ecdsa_priv)  # returns (r, s)

def verify_ballot_ecdsa(ciphertext, signature, ecdsa_pub):
    data = serialize_ciphertext(ciphertext)
    r, s = signature
    return ECDSA_verify(data, r, s, ecdsa_pub)

def sum_elgamal_ciphertexts(ciphertexts_list):
    num_candidates = len(ciphertexts_list[0])
    c1_sum = [ciphertexts_list[0][i][0] for i in range(num_candidates)]
    c2_sum = [ciphertexts_list[0][i][1] for i in range(num_candidates)]

    for ballot in ciphertexts_list[1:]:
        for i in range(num_candidates):
            c1_sum[i] = (c1_sum[i] * ballot[i][0]) % PARAM_P
            c2_sum[i] = (c2_sum[i] * ballot[i][1]) % PARAM_P

    return list(zip(c1_sum, c2_sum))

def decrypt_and_decode_elgamal(c1c2, priv, max_votes):
    c1, c2 = c1c2
    val = EG_decrypt(c1, c2, priv, PARAM_P)  # g^m mod p
    m = bruteLog(PARAM_G, val, PARAM_P)
    if 0 <= m <= max_votes:
        return m
    else:
        return -1

if __name__ == "__main__":
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

    # Encrypt & sign
    all_ciphertexts = []
    for i, vote in enumerate(votes):
        ct = encrypt_ballot_elgamal(vote)
        r_s = sign_ballot_ecdsa(ct, voter_ecdsa_keys[i][0])  # private key
        assert verify_ballot_ecdsa(ct, r_s, voter_ecdsa_keys[i][1]), "ECDSA sig invalid!"
        all_ciphertexts.append((ct, r_s))

    # Verify again and keep only valid
    valid_ciphertexts = []
    for i, (ct, sig) in enumerate(all_ciphertexts):
        if verify_ballot_ecdsa(ct, sig, voter_ecdsa_keys[i][1]):
            valid_ciphertexts.append(ct)

    # Sum
    encrypted_results = sum_elgamal_ciphertexts(valid_ciphertexts)

    # Decrypt
    final_counts = []
    for c1c2 in encrypted_results:
        m = decrypt_and_decode_elgamal(c1c2, election_priv, max_votes=NUM_VOTERS)
        final_counts.append(m)

    print("ElGamal + ECDSA -> Election results:", final_counts)
