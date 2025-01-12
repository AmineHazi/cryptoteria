# votes_oop.py

from election import Election

if __name__ == "__main__":
    # We define a small scenario:
    num_voters = 10
    num_candidates = 5

    # Create an Election instance
    e = Election(num_voters=num_voters, num_candidates=num_candidates)

    # Example votes
    # 10 voters, each chooses 1 out of 5 candidates => 5-bit vector with exactly 1 '1'.
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

    # Run the election with these votes
    results = e.run_election(votes)

    # Print final results
    print("Final Tally (EC ElGamal + DSA):")
    for i, count in enumerate(results):
        print(f"  Candidate_{i+1} -> {count} votes")
