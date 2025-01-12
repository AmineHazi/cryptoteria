# election_elgamal_ecdsa.py

from elgamal_ecdsa_votes.entities import (
    Voter,
    Candidate,
    ElectionAuthority,
    verify_ballot_ecdsa
)
from elgamal import EGA_encrypt, PARAM_P, PARAM_G, bruteLog

class Election:
    def __init__(self, num_voters=10, num_candidates=5):
        self.num_voters = num_voters
        self.num_candidates = num_candidates

        self.authority = ElectionAuthority()
        self.voters = [Voter(i) for i in range(num_voters)]
        self.candidates = [
            Candidate(i, f"Candidate_{i+1}") for i in range(num_candidates)
        ]

    def encrypt_ballot(self, vote_bits):
        ciphertext = []
        for bit in vote_bits:
            c1, c2 = EGA_encrypt(bit, self.authority.pub, PARAM_P, PARAM_G)
            ciphertext.append((c1, c2))
        return ciphertext

    def sum_ballots(self, ballots):
        if not ballots:
            return []

        n = len(ballots[0])
        c1_sum = [ballots[0][i][0] for i in range(n)]
        c2_sum = [ballots[0][i][1] for i in range(n)]

        for ballot in ballots[1:]:
            for i in range(n):
                c1_sum[i] = (c1_sum[i] * ballot[i][0]) % PARAM_P
                c2_sum[i] = (c2_sum[i] * ballot[i][1]) % PARAM_P

        return list(zip(c1_sum, c2_sum))

    def decode_gm(self, gm, max_votes):
        """
        gm = g^m mod p. Brute force in [0..max_votes].
        """
        m = bruteLog(PARAM_G, gm, PARAM_P)
        if 0 <= m <= max_votes:
            return m
        return -1

    def run_election(self, votes):
        # encrypt + sign
        all_ballots = []
        for i, bits in enumerate(votes):
            ct = self.encrypt_ballot(bits)
            sig = self.voters[i].sign_ballot(ct)
            all_ballots.append((ct, sig, i))

        # verify
        valid_ballots = []
        for (ct, sig, i) in all_ballots:
            if verify_ballot_ecdsa(ct, sig, self.voters[i].ecdsa_pub):
                valid_ballots.append(ct)

        # sum
        sum_ct = self.sum_ballots(valid_ballots)

        # decrypt + decode
        results = []
        for (c1, c2) in sum_ct:
            gm = self.authority.decrypt(c1, c2)
            m = self.decode_gm(gm, self.num_voters)
            results.append(m)

        return results
