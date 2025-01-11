# election_elgamal_dsa.py

from entities import (
    Voter,
    Candidate,
    ElectionAuthority,
    verify_ballot_dsa
)
from elgamal import EGA_encrypt, PARAM_P, PARAM_G, bruteLog
from algebra import int_to_bytes

class Election:
    def __init__(self, num_voters=10, num_candidates=5):
        self.num_voters = num_voters
        self.num_candidates = num_candidates

        # Authority with ElGamal keys
        self.authority = ElectionAuthority()

        # Voters (DSA)
        self.voters = [Voter(i) for i in range(num_voters)]

        # Candidates
        self.candidates = [
            Candidate(i, f"Candidate_{i+1}") for i in range(num_candidates)
        ]

    def encrypt_ballot(self, vote_bits):
        """
        'vote_bits' is a list of 0/1 of length num_candidates.
        We use *Additive* ElGamal => EGA_encrypt.
        """
        from elgamal import EGA_encrypt
        ciphertext = []
        for bit in vote_bits:
            c1, c2 = EGA_encrypt(bit, self.authority.pub, PARAM_P, PARAM_G)
            ciphertext.append((c1, c2))
        return ciphertext

    def sum_encrypted_ballots(self, ballots):
        """
        Homomorphic addition in *Additive* ElGamal is done by
        multiplying (c1, c2) pairs: (c1*c1', c2*c2').
        """
        if not ballots:
            return []

        num_candidates = len(ballots[0])
        c1_sum = [ballots[0][i][0] for i in range(num_candidates)]
        c2_sum = [ballots[0][i][1] for i in range(num_candidates)]

        for ballot in ballots[1:]:
            for i in range(num_candidates):
                c1_sum[i] = (c1_sum[i] * ballot[i][0]) % PARAM_P
                c2_sum[i] = (c2_sum[i] * ballot[i][1]) % PARAM_P

        return list(zip(c1_sum, c2_sum))

    def decode_gm(self, gm_val, max_votes):
        """
        We get g^m mod p. We brute force in [0..max_votes].
        """
        from elgamal import bruteLog, PARAM_G, PARAM_P
        m = bruteLog(PARAM_G, gm_val, PARAM_P)
        if m != -1 and m <= max_votes:
            return m
        return -1

    def run_election(self, votes):
        # Check we have correct number of votes
        assert len(votes) == self.num_voters

        # Each voter encrypts + signs
        all_ballots = []
        for i, vote_bits in enumerate(votes):
            ct = self.encrypt_ballot(vote_bits)
            signature = self.voters[i].sign_ballot(ct)
            all_ballots.append((ct, signature, i))

        # Verify signatures
        valid_ciphertexts = []
        for (ct, sig, i) in all_ballots:
            if verify_ballot_dsa(ct, sig, self.voters[i].dsa_pub):
                valid_ciphertexts.append(ct)
            # else: discard

        # Sum
        if not valid_ciphertexts:
            return [0]*self.num_candidates
        sum_cipher = self.sum_encrypted_ballots(valid_ciphertexts)

        # Decrypt & decode
        results = []
        for (c1, c2) in sum_cipher:
            gm = self.authority.decrypt(c1, c2)
            m = self.decode_gm(gm, self.num_voters)
            results.append(m)

        return results

