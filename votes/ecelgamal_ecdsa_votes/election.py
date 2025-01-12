# election.py

from ecelgamal_ecdsa_votes.entities import Voter, Candidate, ElectionAuthority, serialize_ec_ciphertext
from ecelgamal import ECEG_encrypt, BaseU, BaseV
from ecdsa import ECDSA_verify
from rfc7748 import add
from algebra import int_to_bytes

p = 2**255 - 19

class Election:
    def __init__(self, num_voters=10, num_candidates=5):
        self.num_voters = num_voters
        self.num_candidates = num_candidates

        # Initialize the election authority (EC ElGamal)
        self.authority = ElectionAuthority()

        # Create Voters
        self.voters = [Voter(i) for i in range(num_voters)]

        # Create Candidates
        # e.g. default candidate names
        self.candidates = [
            Candidate(i, f"Candidate_{i+1}") for i in range(num_candidates)
        ]

    def encrypt_ballot(self, vote):
        """
        Each 'vote' is a list of 5 bits [0, 1, 0, ...].
        We use the authority's public key to EC ElGamal encrypt each bit.
        """
        ciphertext = []
        for bit in vote:
            # ECEG_encrypt(message, public_key)
            R, S = ECEG_encrypt(bit, self.authority.public_key)
            ciphertext.append((R, S))
        return ciphertext

    def sum_encrypted_ballots(self, ballots):
        """
        Homomorphically sum EC ElGamal ballots.
        ballots is a list of ciphertext lists:
          [ [ (R0,S0), (R1,S1), ... ], [ ... ], ... ]
        """
        if not ballots:
            return []

        num_candidates = len(ballots[0])
        # Initialize with the first ballot
        R_sum = [ballots[0][i][0] for i in range(num_candidates)]
        S_sum = [ballots[0][i][1] for i in range(num_candidates)]

        for ballot in ballots[1:]:
            for i in range(num_candidates):
                Rx_sum, Ry_sum = R_sum[i]
                Rx_ball, Ry_ball = ballot[i][0]
                R_sum[i] = add(Rx_sum, Ry_sum, Rx_ball, Ry_ball, p)

                Sx_sum, Sy_sum = S_sum[i]
                Sx_ball, Sy_ball = ballot[i][1]
                S_sum[i] = add(Sx_sum, Sy_sum, Sx_ball, Sy_ball, p)

        return list(zip(R_sum, S_sum))

    def decode_point(self, M_point, max_votes):
        """
        Brute force decode M_point in [0..max_votes].
        We check repeated additions of (BaseU, BaseV).
        """
        candidate = (1, 0)  # Infinity => 0
        for m in range(max_votes+1):
            if candidate == M_point:
                return m
            candidate = add(candidate[0], candidate[1], BaseU, BaseV, p)
        return -1


    def run_election(self, votes):
        """
        Main procedure:
          1) Each voter encrypts + signs ballot
          2) Check signatures
          3) Sum valid ballots
          4) Decrypt + decode
        """
        assert len(votes) == self.num_voters, "Mismatch in number of voters/votes"

        # Step 1: Each voter produces (ciphertext, signature)
        all_encrypted_ballots = []
        for i, vote_bits in enumerate(votes):
            voter = self.voters[i]
            ballot_ciphertext = self.encrypt_ballot(vote_bits)
            signature = voter.sign_ballot(ballot_ciphertext)

            # We'll store (ciphertext, signature, voter_id) 
            all_encrypted_ballots.append((ballot_ciphertext, signature, i))

        # Step 2: Verify signatures, keep valid ballots
        valid_ballots = []
        for (ct, sig, i) in all_encrypted_ballots:
            voter_pub = self.voters[i].ecdsa_pub
            data = serialize_ec_ciphertext(ct)

            # We can also re-check with ecdsa.py if needed:
            (r, s) = sig
            if ECDSA_verify(data, r, s, voter_pub):
                valid_ballots.append(ct)

        # Step 3: Homomorphically sum
        if not valid_ballots:
            return [0]*self.num_candidates

        sum_ciphertext = self.sum_encrypted_ballots(valid_ballots)

        # Step 4: Decrypt + decode
        results = []
        for (R, S) in sum_ciphertext:
            M_point = self.authority.decrypt_point(R, S)
            count = self.decode_point(M_point, max_votes=self.num_voters)
            results.append(count)

        return results
