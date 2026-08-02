from pathlib import Path
from contextlib import closing

from caretaker import SQLiteRepairStore
from caretaker.policy import RepairPolicy


def test_sqlite_store_persists_policy_stream(tmp_path: Path) -> None:
    store = SQLiteRepairStore(tmp_path / "caretaker.sqlite")
    snapshot = RepairPolicy().snapshot()
    store.record_policy(snapshot)

    import sqlite3

    with closing(sqlite3.connect(tmp_path / "caretaker.sqlite")) as connection:
        row = connection.execute(
            "SELECT payload FROM policy_snapshots WHERE record_id = ?",
            (str(snapshot.policy_snapshot_id),),
        ).fetchone()
    assert row is not None
    assert snapshot.fingerprint in row[0]
    assert "human_readable_policy" in row[0]
