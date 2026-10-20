import pytest

from auth_service.bloom.filter import BloomFilter


def test_added_items_are_found():
    bloom = BloomFilter(expected_items=1000, false_positive_rate=0.01)
    words = [f"password{i}" for i in range(1000)]
    for word in words:
        bloom.add(word)
    assert all(word in bloom for word in words)


def test_empty_filter_finds_nothing():
    bloom = BloomFilter(expected_items=1000, false_positive_rate=0.01)
    assert "qwerty" not in bloom


def test_false_positive_rate_is_close_to_target():
    n = 10_000
    bloom = BloomFilter(expected_items=n, false_positive_rate=0.01)
    for i in range(n):
        bloom.add(f"leaked-{i}")
    probes = 20_000
    false_positives = sum(f"other-{i}" in bloom for i in range(probes))
    assert false_positives / probes < 0.02


def test_parameters_follow_formulas():
    bloom = BloomFilter(expected_items=1_000_000, false_positive_rate=0.01)
    assert bloom.size_bits == pytest.approx(9_585_059, rel=0.01)
    assert bloom.num_hashes == 7


def test_save_and_load_roundtrip(tmp_path):
    bloom = BloomFilter(expected_items=100, false_positive_rate=0.01)
    bloom.add("hunter2")
    path = tmp_path / "filter.bloom"
    bloom.save(path)

    loaded = BloomFilter.load(path)
    assert "hunter2" in loaded
    assert "not-added" not in loaded
