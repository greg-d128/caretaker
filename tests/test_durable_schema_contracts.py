from __future__ import annotations

import sqlite3

import pytest

from caretaker.evidence.store import SQLiteEvidenceStore
from caretaker.store import SQLiteRepairStore


def _database_with_version(path, metadata_table: str, version: str) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        f"CREATE TABLE {metadata_table} (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(
        f"INSERT INTO {metadata_table}(key, value) VALUES ('schema_version', ?)",
        (version,),
    )
    connection.commit()
    connection.close()


def test_repair_store_rejects_unknown_schema_version(tmp_path):
    path = tmp_path / "repair.sqlite"
    _database_with_version(path, "caretaker_store_metadata", "8")

    with pytest.raises(ValueError, match="Unsupported Caretaker repair store schema version"):
        SQLiteRepairStore(path)


def test_evidence_store_rejects_unknown_schema_version(tmp_path):
    path = tmp_path / "evidence.sqlite"
    _database_with_version(path, "evidence_metadata", "2")

    with pytest.raises(ValueError, match="Unsupported Caretaker evidence store schema version"):
        SQLiteEvidenceStore(path)


def test_new_stores_record_explicit_schema_versions(tmp_path):
    repair = SQLiteRepairStore(tmp_path / "repair.sqlite")
    evidence = SQLiteEvidenceStore(tmp_path / "evidence.sqlite")

    assert repair.schema_version == 9
    assert evidence.schema_version == 1
