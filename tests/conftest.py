"""Shared pytest fixtures for unit and integration testing."""

from pathlib import Path

import pytest

from rbacapi.config.settings import Settings


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    """Provide isolated configuration with low Argon2 cost for fast test execution."""
    return Settings(
        secret_key="test-secret-key-32-bytes-long-for-testing-purpose",  # nosec B105
        db_path=tmp_path / "test_rbac.db",
        argon2_time_cost=1,
        argon2_memory_cost=1024,
        argon2_parallelism=1,
    )
