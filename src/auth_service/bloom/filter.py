import hashlib
import math
from pathlib import Path


class BloomFilter:
    def __init__(self, expected_items: int, false_positive_rate: float) -> None:
        self.expected_items = expected_items
        self.false_positive_rate = false_positive_rate
        self.size_bits = math.ceil(
            -expected_items * math.log(false_positive_rate) / (math.log(2) ** 2)
        )
        self.num_hashes = max(1, round(self.size_bits / expected_items * math.log(2)))
        self._bits = bytearray((self.size_bits + 7) // 8)

    def _positions(self, item: str) -> list[int]:
        digest = hashlib.blake2b(item.encode(), digest_size=16).digest()
        h1 = int.from_bytes(digest[:8], "big")
        h2 = int.from_bytes(digest[8:], "big")
        return [(h1 + i * h2) % self.size_bits for i in range(self.num_hashes)]

    def add(self, item: str) -> None:
        for pos in self._positions(item):
            self._bits[pos // 8] |= 1 << (pos % 8)

    def __contains__(self, item: str) -> bool:
        return all(self._bits[pos // 8] & (1 << (pos % 8)) for pos in self._positions(item))

    def save(self, path: str | Path) -> None:
        header = f"{self.expected_items},{self.false_positive_rate}\n".encode()
        Path(path).write_bytes(header + bytes(self._bits))

    @classmethod
    def load(cls, path: str | Path) -> "BloomFilter":
        header, bits = Path(path).read_bytes().split(b"\n", 1)
        expected_items, false_positive_rate = header.decode().split(",")
        bloom = cls(int(expected_items), float(false_positive_rate))
        bloom._bits = bytearray(bits)
        return bloom
