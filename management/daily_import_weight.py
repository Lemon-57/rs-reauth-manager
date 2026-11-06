"""Durable, process-safe Pro/ProLite import ordering by Beijing calendar day."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from contextlib import closing
import sqlite3

BEIJING = timezone(timedelta(hours=8))


class DailyImportWeight:
    def __init__(self, path, clock=None):
        self.path = Path(path)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @classmethod
    def initialize(cls, path):
        """Explicit provisioning only; runtime never recreates a missing ledger."""
        path = Path(path)
        with path.open('xb'):
            pass
        path.chmod(0o600)
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE assignments (account TEXT NOT NULL, slot INTEGER NOT NULL, '
                       'day TEXT NOT NULL, ordinal INTEGER NOT NULL, weight INTEGER NOT NULL '
                       'CHECK(weight BETWEEN 1 AND 100), PRIMARY KEY(account, slot), UNIQUE(day, ordinal))')
            db.execute('PRAGMA user_version=1')
        return cls(path)

    def reserve(self, account_id, slot):
        if not isinstance(account_id, str) or not account_id or type(slot) is not int or slot < 1:
            raise ValueError('invalid_import_weight_identity')
        # mode=rw fails closed if recovery accidentally removes the ledger.
        with closing(sqlite3.connect(self.path.resolve().as_uri() + '?mode=rw', uri=True, timeout=10)) as db, db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            if db.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise ValueError('unknown_import_weight_schema')
            previous = db.execute('SELECT day, ordinal, weight FROM assignments WHERE account=? AND slot=?',
                                  (account_id, slot)).fetchone()
            if previous:
                day, ordinal, weight = previous
            else:
                moment = self.clock()
                if moment.tzinfo is None:
                    raise ValueError('weight_clock_requires_timezone')
                day = moment.astimezone(BEIJING).date().isoformat()
                ordinal = db.execute('SELECT COALESCE(MAX(ordinal),0)+1 FROM assignments WHERE day=?',
                                     (day,)).fetchone()[0]
                weight = max(1, 101 - ordinal)
                db.execute('INSERT INTO assignments VALUES (?,?,?,?,?)',
                           (account_id, slot, day, ordinal, weight))
            return {'weight': weight, 'day': day, 'ordinal': ordinal, 'timezone': 'Asia/Shanghai'}
