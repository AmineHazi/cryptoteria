#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt
from dsa import (
    DSA_generate_keys,
    DSA_sign,
    DSA_verify
)
from rfc7748 import add
from algebra import int_to_bytes

p = 2**255 - 19

NUM_VOTERS = 10
NUM_CANDIDATES = 5

# ELECTION AUTHORITY -> EC ElGamal
election_priv, election_pub = ECEG_generate_keys()

# VOTERS -> DSA
voter_dsa_keys = [DSA_generate_keys() for _ in range(NUM_VOTERS)]

def encrypt_ballot_ecelgamal(vote):
    """
    EC ElGamal encryption of each bit (0 or 1).
    Returns [(R_i, S_i), ...].
    """
    ciphertext = []
    for bit in vote:
        R, S = ECEG_encrypt(bit, election_pub)
        ciphertext.append((R, S))
    return ciphertext

def serialize_ec_ciphertext(ciphertext):
    """
    Convert list of pairs [(Rx,Ry),(Sx,Sy)] to bytes for DSA hashing.
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

def sign_ballot_dsa(ciphertext, dsa_priv):
    data = serialize_ec_ciphertext(ciphertext)
    r, s = DSA_sign(data, dsa_priv)
    return (r, s)

def verify_ballot_dsa(ciphertext, signature, dsa_pub):
    data = serialize_ec_ciphertext(ciphertext)
    r, s = signature
    return DSA_verify(data, r, s, dsa_pub)

def sum_ec_ciphertexts(ciphertexts):
    """
    Homomorphic addition of EC ElGamal:
      (R1,S1)+(R2,S2)=(R1+R2, S1+S2).
    """
    num_candidates = len(ciphertexts[0])
    R_sum = [ciphertexts[0][i][0] for i in range(num_candidates)]
    S_sum = [ciphertexts[0][i][1] for i in range(num_candidates)]

    for ballot in ciphertexts[1:]:
        for i in range(num_candidates):
            # R_sum[i] and ballot[i][0] are points
            Rx_sum, Ry_sum = R_sum[i]
            Rx_ball, Ry_ball = ballot[i][0]
            R_sum[i] = add(Rx_sum, Ry_sum, Rx_ball, Ry_ball, p)

            Sx_sum, Sy_sum = S_sum[i]
            Sx_ball, Sy_ball = ballot[i][1]
            S_sum[i] = add(Sx_sum, Sy_sum, Sx_ball, Sy_ball, p)

    return list(zip(R_sum, S_sum))

def decode_point_ec(M, max_votes):
    from rfc7748 import add
    from ecelgamal import BaseU, BaseV
    candidate = (1, 0)  # Infinity => 0
    for m in range(max_votes+1):
        if candidate == M:
            return m
        candidate = add(candidate[0], candidate[1], BaseU, BaseV, p)
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

    # Encrypt + sign
    all_ciphertexts = []
    for i, vote in enumerate(votes):
        ct = encrypt_ballot_ecelgamal(vote)
        sig = sign_ballot_dsa(ct, voter_dsa_keys[i][0])
        assert verify_ballot_dsa(ct, sig, voter_dsa_keys[i][1]), "DSA signature invalid!"
        all_ciphertexts.append((ct, sig))

    # filter valid
    valid_ciphertexts = []
    for i,(ct,sig) in enumerate(all_ciphertexts):
        if verify_ballot_dsa(ct, sig, voter_dsa_keys[i][1]):
            valid_ciphertexts.append(ct)

    # sum
    encrypted_results = sum_ec_ciphertexts(valid_ciphertexts)

    # decrypt
    final_counts = []
    for (R, S) in encrypted_results:
        M = ECEG_decrypt(R, S, election_priv)
        candidate_count = decode_point_ec(M, max_votes=NUM_VOTERS)
        final_counts.append(candidate_count)

    print("EC ElGamal + DSA -> Election results:", final_counts)
