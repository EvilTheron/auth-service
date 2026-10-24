import sys
from pathlib import Path

from auth_service.bloom.filter import BloomFilter


def main(source: str, target: str, false_positive_rate: float = 0.001) -> None:
    with open(source, encoding="utf-8", errors="ignore") as f:
        passwords = {line.strip() for line in f if line.strip()}

    bloom = BloomFilter(expected_items=len(passwords), false_positive_rate=false_positive_rate)
    for password in passwords:
        bloom.add(password)

    Path(target).parent.mkdir(parents=True, exist_ok=True)
    bloom.save(target)
    size_kib = bloom.size_bits / 8 / 1024
    print(f"{len(passwords)} passwords, {size_kib:.0f} KiB, {bloom.num_hashes} hashes")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
