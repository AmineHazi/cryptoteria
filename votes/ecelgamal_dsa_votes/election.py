# election_ecelgamal_dsa.py

from entities import (
    Voter,
    Candidate,
    ElectionAuthority,
    verify_ballot_dsa
)
from rfc7748 import add
from ecelgamal import ECEG_encrypt, ECEG_decrypt
from algebra import int_to_bytes

p = 2**255 - 19

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
        """
        vote_bits: [0 or 1,...] length = num_candidates
        returns list of (R, S) pairs
        """
        ciphertext = []
        for bit in vote_bits:
            R, S = ECEG_encrypt(bit, self.authority.pub)
            ciphertext.append((R, S))
        return ciphertext

    def sum_ballots(self, all_ciphertexts):
        """
        Homomorphic sum:
         (R1,S1)+(R2,S2)=(R1+R2, S1+S2).
        """
        if not all_ciphertexts:
            return []

        n = len(all_ciphertexts[0])
        R_sum = [all_ciphertexts[0][i][0] for i in range(n)]
        S_sum = [all_ciphertexts[0][i][1] for i in range(n)]

        for ballot in all_ciphertexts[1:]:
            for i in range(n):
                Rx_sum, Ry_sum = R_sum[i]
                Rx_ball, Ry_ball = ballot[i][0]
                R_sum[i] = add(Rx_sum, Ry_sum, Rx_ball, Ry_ball, p)

                Sx_sum, Sy_sum = S_sum[i]
                Sx_ball, Sy_ball = ballot[i][1]
                S_sum[i] = add(Sx_sum, Sy_sum, Sx_ball, Sy_ball, p)

        return list(zip(R_sum, S_sum))

    def decode_point(self, M_point, max_votes):
        """
        Brute force from 0..max_votes on the curve.
        """
        from rfc7748 import add
        from ecelgamal import BaseU, BaseV
        candidate = (1,0)
        for m in range(max_votes+1):
            if candidate == M_point:
                return m
            candidate = add(candidate[0], candidate[1], BaseU, BaseV, p)
        return -1

    def run_election(self, votes):
        assert len(votes) == self.num_voters

        all_ballots = []
        for i, bits in enumerate(votes):
            ct = self.encrypt_ballot(bits)
            sig = self.voters[i].sign_ballot(ct)
            all_ballots.append((ct, sig, i))

        # verify
        valid_ciphertexts = []
        for (ct, sig, i) in all_ballots:
            if verify_ballot_dsa(ct, sig, self.voters[i].dsa_pub):
                valid_ciphertexts.append(ct)

        # sum
        summed = self.sum_ballots(valid_ciphertexts)

        # decrypt & decode
        results = []
        for (R, S) in summed:
            M_point = self.authority.decrypt_point(R, S)
            count = self.decode_point(M_point, max_votes=self.num_voters)
            results.append(count)

        return results
