# votes.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from rfc7748 import add
from algebra import int_to_bytes
from Crypto.Hash import SHA256

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

###############################################################################
# 1. ELECTION AUTHORITY KEYS (EC ELGAMAL)
###############################################################################
election_private_key, election_public_key = ECEG_generate_keys()

###############################################################################
# 2. VOTER KEY GENERATION (EACH VOTER HAS AN ECDSA KEY PAIR)
###############################################################################
NUM_VOTERS = 10
NUM_CANDIDATES = 5

voter_keys = []
for _ in range(NUM_VOTERS):
    priv, pub = ECDSA_generate_keys()
    voter_keys.append((priv, pub))

###############################################################################
# 3. HELPER FUNCTIONS
###############################################################################
def encrypt_ballot(vote):
    """
    Encrypts a ballot using the election authority's public key.
    vote: list of 0/1 for the chosen candidate(s).
    Returns: list of (R_i, S_i) for each candidate.
    """
    return [ECEG_encrypt(v, election_public_key) for v in vote]

def serialize_ciphertext(ciphertext):
    """
    Convert the ciphertext (list of pairs of points) into bytes for hashing/signing.
    ciphertext = [(R1, S1), (R2, S2), ..., (R5, S5)]
      where R1 = (Rx1, Ry1), S1 = (Sx1, Sy1), etc.
    """
    data = b""
    for (R, S) in ciphertext:
        # R, S are points (Rx, Ry), (Sx, Sy) on the curve.
        Rx, Ry = R
        Sx, Sy = S
        # Convert them to bytes in a consistent way (e.g., 32 bytes each).
        data += Rx.to_bytes(32, byteorder='big')
        data += Ry.to_bytes(32, byteorder='big')
        data += Sx.to_bytes(32, byteorder='big')
        data += Sy.to_bytes(32, byteorder='big')
    return data

def sign_ballot(ciphertext, voter_private_key):
    """
    Signs the entire ciphertext with the voter's ECDSA private key.
    Returns (r, s).
    """
    data = serialize_ciphertext(ciphertext)
    return ECDSA_sign(data, voter_private_key)

def verify_ballot(ciphertext, signature, voter_public_key):
    """
    Verifies the ballot's signature using ECDSA and the voter's public key.
    Returns True/False.
    """
    data = serialize_ciphertext(ciphertext)
    r, s = signature
    return ECDSA_verify(data, r, s, voter_public_key)

def sum_encrypted_votes(all_ciphertexts):
    """
    Homomorphically sums all encrypted ballots.
    all_ciphertexts: list of ballots, each is [(R_i, S_i), (R_i, S_i), ...].
    Returns: [(R_sum_i, S_sum_i), ...] for each candidate i.
    """
    num_candidates = len(all_ciphertexts[0])
    # Initialize with the first ciphertext
    R_sum = [all_ciphertexts[0][i][0] for i in range(num_candidates)]
    S_sum = [all_ciphertexts[0][i][1] for i in range(num_candidates)]

    for ciphertext in all_ciphertexts[1:]:
        for i in range(num_candidates):
            R_sum[i] = add(R_sum[i][0], R_sum[i][1],
                           ciphertext[i][0][0], ciphertext[i][0][1], p)
            S_sum[i] = add(S_sum[i][0], S_sum[i][1],
                           ciphertext[i][1][0], ciphertext[i][1][1], p)

    return list(zip(R_sum, S_sum))

def ECEG_decrypt_point(R, S, priv):
    """
    Decrypts an EC ElGamal ciphertext with the private key 'priv'
    and returns the resulting point on the curve.
    """
    return ECEG_decrypt(R, S, priv)

def decode_point(M, max_votes):
    """
    Brute force the integer m in [0..max_votes], so that M = m * G.
    """
    from rfc7748 import add
    from ecelgamal import BaseU, BaseV
    candidate = (1, 0)  # 0 on the curve
    for m in range(max_votes + 1):
        if candidate == M:
            return m
        candidate = add(candidate[0], candidate[1], BaseU, BaseV, p)
    raise ValueError("Could not decode point M.")

###############################################################################
# 4. SIMULATE THE VOTING
###############################################################################
if __name__ == "__main__":
    # Example: 10 voters, 5 candidates
    # Each voter chooses 1 candidate => list of length 5 with one '1'.
    votes = [
        [1, 0, 0, 0, 0],
        [0, 1, 0, 0, 0],
        [0, 0, 1, 0, 0],
        [0, 0, 0, 1, 0],
        [0, 0, 0, 0, 1],
        [1, 0, 0, 0, 0],
        [0, 1, 0, 0, 0],
        [1, 0, 0, 0, 0],
        [0, 0, 1, 0, 0],
        [0, 0, 0, 1, 0],
    ]

    # 1) Each voter encrypts + signs their ballot
    all_ciphertexts = []
    for voter_id, vote in enumerate(votes):
        ciphertext = encrypt_ballot(vote)
        signature = sign_ballot(ciphertext, voter_keys[voter_id][0])
        # Verify right away (optional, but recommended)
        assert verify_ballot(ciphertext, signature, voter_keys[voter_id][1]), \
            f"Signature of voter {voter_id} is invalid!"
        
        # Store (ciphertext, signature) so the server can re-verify if needed
        all_ciphertexts.append((ciphertext, signature))

    # 2) The server verifies all signatures, discards invalid ballots
    valid_ciphertexts = []
    for i, (ciphertext, signature) in enumerate(all_ciphertexts):
        voter_pub = voter_keys[i][1]
        if verify_ballot(ciphertext, signature, voter_pub):
            valid_ciphertexts.append(ciphertext)
        else:
            print(f"Ballot from voter {i} is invalid and will be discarded.")

    # 3) Homomorphically sum the (valid) encrypted votes
    encrypted_results = sum_encrypted_votes(valid_ciphertexts)

    # 4) Decrypt the result
    final_counts = []
    for (R, S) in encrypted_results:
        M_point = ECEG_decrypt_point(R, S, election_private_key)
        candidate_count = decode_point(M_point, max_votes=NUM_VOTERS)
        final_counts.append(candidate_count)

    print("Election results (votes per candidate):", final_counts)
