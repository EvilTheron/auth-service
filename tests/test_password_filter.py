from pathlib import Path

import pytest

from auth_service.api.deps import _load_filter, get_password_filter
from auth_service.bloom.filter import BloomFilter
from auth_service.core.config import get_settings
from tests.helpers import make_filter


def test_load_filter_reads_saved_file(tmp_path: Path):
    path = tmp_path / "leaked.bloom"
    make_filter("password123").save(path)
    loaded = _load_filter(str(path))
    assert loaded is not None
    assert "password123" in loaded


def test_load_filter_without_file_returns_none(tmp_path: Path):
    assert _load_filter(str(tmp_path / "missing.bloom")) is None


def test_get_password_filter_uses_configured_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "other.bloom"
    make_filter("hunter2").save(path)
    monkeypatch.setattr(get_settings(), "leaked_passwords_filter_path", str(path))
    bloom = get_password_filter()
    assert bloom is not None
    assert "hunter2" in bloom


def test_truncated_filter_file_is_rejected(tmp_path: Path):
    path = tmp_path / "broken.bloom"
    make_filter("password123").save(path)
    path.write_bytes(path.read_bytes()[:-5])  # e.g. truncated while copying

    with pytest.raises(ValueError, match="corrupted"):
        BloomFilter.load(path)
    assert _load_filter(str(path)) is None
