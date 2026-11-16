"""Fail closed unless tests target a dedicated PostgreSQL test database.

The API tests exercise real persistence and import the production session factory. This
guard runs before test modules are imported so .env development credentials cannot route
test-created scans into the analyst's local workspace database.
"""

import os

import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


def pytest_configure() -> None:
    test_database_url = os.environ.get("TEST_DATABASE_URL", "").strip()
    if not test_database_url:
        raise pytest.UsageError(
            "Set TEST_DATABASE_URL to a dedicated PostgreSQL database whose name ends "
            "in _test or _testing before running backend tests."
        )

    try:
        parsed_url = make_url(test_database_url)
    except (ArgumentError, TypeError, ValueError) as exc:
        raise pytest.UsageError(
            "TEST_DATABASE_URL must be a valid PostgreSQL URL for a dedicated test database."
        ) from exc

    database_name = (parsed_url.database or "").lower()
    if parsed_url.get_backend_name() != "postgresql" or not database_name.endswith(
        ("_test", "_testing")
    ):
        raise pytest.UsageError(
            "TEST_DATABASE_URL must target PostgreSQL and a database named with _test "
            "or _testing suffix."
        )

    # Do this before importing test modules: app.core.config and app.db.session are
    # initialized at module import time and otherwise may consume the project's .env.
    os.environ["DATABASE_URL"] = test_database_url
    os.environ["ENVIRONMENT"] = "testing"
