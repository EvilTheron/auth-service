import random
import string
import sys
import time

from auth_service.bloom.filter import BloomFilter


def random_word(rng: random.Random) -> str:
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=12))


def main(n: int = 500_000, p: float = 0.01) -> None:
    rng = random.Random(42)
    words = {random_word(rng) for _ in range(n)}

    bloom = BloomFilter(expected_items=len(words), false_positive_rate=p)
    for word in words:
        bloom.add(word)

    probes = [w for w in (random_word(rng) for _ in range(200_000)) if w not in words]
    start = time.perf_counter()
    false_positives = sum(1 for w in probes if w in bloom)
    elapsed = time.perf_counter() - start

    set_bytes = sys.getsizeof(words) + sum(sys.getsizeof(w) for w in words)
    print(f"Items: {len(words)}, target false positive rate: {p}")
    print(f"Bloom filter: {bloom.size_bytes / 1024 / 1024:.2f} MiB, {bloom.num_hashes} hashes")
    print(f"Python set:   {set_bytes / 1024 / 1024:.2f} MiB")
    print(f"Measured false positive rate: {false_positives / len(probes):.4f}")
    print(f"Lookup time: {elapsed / len(probes) * 1e6:.1f} microseconds per item")


if __name__ == "__main__":
    main()
