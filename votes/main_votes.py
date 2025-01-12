# main_vote.py

from elgamal_dsa_votes.election import Election as ElectionElGamalDSA
from elgamal_ecdsa_votes.election import Election as ElectionElGamalECDSA
from ecelgamal_dsa_votes.election import Election as ElectionECElGamalDSA
from ecelgamal_ecdsa_votes.election import Election as ElectionECElGamalECDSA

def print_results(title, results):
  print(f"\n=== {title} ===")
  for i, result in enumerate(results):
    print(f"Candidate {i + 1}: {result}")

def main():
    # Example votes for a system with 10 voters and 5 candidates
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


    print_results("ElGamal + DSA", ElectionElGamalDSA(num_voters=10, num_candidates=5).run_election(votes))
    print_results("ElGamal + ECDSA", ElectionElGamalECDSA(num_voters=10, num_candidates=5).run_election(votes))
    print_results("EC ElGamal + DSA", ElectionECElGamalDSA(num_voters=10, num_candidates=5).run_election(votes))
    print_results("EC ElGamal + ECDSA", ElectionECElGamalECDSA(num_voters=10, num_candidates=5).run_election(votes))

if __name__ == "__main__":
    main()
