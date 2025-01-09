from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt, bruteECLog
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from rfc7748 import add
from random import randint
from algebra import mod_inv, int_to_bytes
from Crypto.Hash import SHA256

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)


# Hash function
def H(data):
    """Compute the SHA256 hash of the input data."""
    if isinstance(data, int):
        data = int_to_bytes(data)  # Convert integer to bytes
    hash_obj = SHA256.new(data)
    return int(hash_obj.hexdigest(), 16)


# Sign and verify ballots
def sign_ballot(vote, ecdsa_private_key):
    ballot_hash = H(sum(vote))  # Simple hash of the ballot sum
    return ECDSA_sign(int_to_bytes(ballot_hash), ecdsa_private_key)


def verify_ballot(vote, signature, ecdsa_public_key):
    ballot_hash = H(sum(vote))  # Simple hash of the ballot sum
    return ECDSA_verify(int_to_bytes(ballot_hash), signature[0], signature[1], ecdsa_public_key)


# Generate voting keys for voters
def generate_voter_keys(num_voters):
    voter_keys = {}
    for i in range(1, num_voters + 1):
        voter_keys[i] = {
            "private_key": None,
            "public_key": None,
            "ecdsa": ECDSA_generate_keys(),
        }
        voter_keys[i]["private_key"], voter_keys[i]["public_key"] = ECEG_generate_keys()
    return voter_keys


# Encrypt ballot for a single voter
def encrypt_ballot(vote, voter_public_key):
    return [ECEG_encrypt(v, voter_public_key) for v in vote]


# Sum encrypted votes homomorphically
def sum_encrypted_votes(encrypted_votes):
    num_candidates = len(encrypted_votes[0])
    R_sum = [encrypted_votes[0][i][0] for i in range(num_candidates)]
    S_sum = [encrypted_votes[0][i][1] for i in range(num_candidates)]

    for encrypted_ballot in encrypted_votes[1:]:
        for i in range(num_candidates):
            R_sum[i] = add(R_sum[i][0], R_sum[i][1], encrypted_ballot[i][0][0], encrypted_ballot[i][0][1], p)
            S_sum[i] = add(S_sum[i][0], S_sum[i][1], encrypted_ballot[i][1][0], encrypted_ballot[i][1][1], p)

    return list(zip(R_sum, S_sum))


# Decrypt the results using the election private key
def decrypt_results(encrypted_results, election_private_key):
    decrypted_votes = []
    for R, S in encrypted_results:
        M = ECEG_decrypt(R, S, election_private_key)
        decrypted_votes.append(bruteECLog(BaseU, M, p))
    return decrypted_votes


# Voting system
if __name__ == "__main__":
    num_voters = 10
    num_candidates = 5

    # Generate keys for voters
    voter_keys = generate_voter_keys(num_voters)

    # Collect votes (Example votes: each voter votes for one candidate)
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

    # Encrypt votes and sign ballots
    encrypted_votes = []
    for voter_id, vote in enumerate(votes, 1):
        encrypted_ballot = encrypt_ballot(vote, voter_keys[voter_id]["public_key"])
        signature = sign_ballot(vote, voter_keys[voter_id]["ecdsa"][0])
        assert verify_ballot(vote, signature, voter_keys[voter_id]["ecdsa"][1]), "Signature verification failed!"
        encrypted_votes.append(encrypted_ballot)

    # Sum encrypted votes homomorphically
    encrypted_results = sum_encrypted_votes(encrypted_votes)

    # Decrypt results (assuming election private key)
    election_private_key = randint(1, ORDER - 1)  # Replace with actual election private key
    decrypted_results = decrypt_results(encrypted_results, election_private_key)

    print("Election results (votes per candidate):", decrypted_results)
