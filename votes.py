from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt
from rfc7748 import add
from algebra import int_to_bytes
from Crypto.Hash import SHA256

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

# Generating the election authority's keys
election_private_key, election_public_key = ECEG_generate_keys()

def encrypt_ballot(vote):
    """
    Encrypts a ballot using the election authority's public key.

    Args:
        vote (list): A list of 0/1 for the chosen candidate(s).

    Returns:
        list: A list of (R_i, S_i) tuples for each candidate.
    """
    return [ECEG_encrypt(v, election_public_key) for v in vote]

def sum_encrypted_votes(encrypted_votes):
    """
    Homomorphically sums encrypted votes.

    Args:
        encrypted_votes (list): A list of ballots, 
                                each ballot is a list of (R_i, S_i) tuples for i in [0..num_candidates-1].

    Returns:
        list: A list of (R_sum_i, S_sum_i) tuples for i in [0..num_candidates-1].
    """
    num_candidates = len(encrypted_votes[0])
    # Initialize R_sum, S_sum with the first ballot
    R_sum = [encrypted_votes[0][i][0] for i in range(num_candidates)]
    S_sum = [encrypted_votes[0][i][1] for i in range(num_candidates)]

    for ballot in encrypted_votes[1:]:
        for i in range(num_candidates):
            R_sum[i] = add(R_sum[i][0], R_sum[i][1],
                           ballot[i][0][0], ballot[i][0][1], p)
            S_sum[i] = add(S_sum[i][0], S_sum[i][1],
                           ballot[i][1][0], ballot[i][1][1], p)

    return list(zip(R_sum, S_sum))

def ECEG_decrypt_point(R, S, private_key):
    """
    Decrypts an encrypted point using the election authority's private key.

    Args:
        R (tuple): The R component of the encrypted point.
        S (tuple): The S component of the encrypted point.
        private_key (tuple): The election authority's private key.

    Returns:
        tuple: The decrypted point M.
    """
    return ECEG_decrypt(R, S, private_key)  # Adjust ecelgamal.py to return the point!

def decode_point(M, max_votes):
    """
    Decodes a point to an integer by brute force.

    Args:
        M (tuple): The point to decode.
        max_votes (int): The maximum number of votes.

    Returns:
        int: The decoded integer.
    """
    from rfc7748 import add
    from ecelgamal import BaseU, BaseV
    candidate = (1, 0)  # Infinity => 0
    for m in range(max_votes + 1):
        if candidate == M:
            return m
        candidate = add(candidate[0], candidate[1], BaseU, BaseV, p)
    raise ValueError("Could not decode point M.")

if __name__ == "__main__":
    num_voters = 10
    num_candidates = 5

    # Example votes
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

    # Ecrypt all votes using the election authority's public key
    encrypted_votes = [encrypt_ballot(vote) for vote in votes]

    # Homomorphically sum all encrypted votes
    encrypted_results = sum_encrypted_votes(encrypted_votes)

    # Decrypt the result
    final_counts = []
    for (R, S) in encrypted_results:
        # 1) Decrypt to get the "summed" point M
        M_point = ECEG_decrypt_point(R, S, election_private_key)
        # 2) Brute force decode that point to an integer
        candidate_count = decode_point(M_point, max_votes=num_voters)
        final_counts.append(candidate_count)

    print("Election results (votes per candidate):", final_counts)
