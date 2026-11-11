"""按北京时间为两组导入套餐分配持久化、幂等的每日权重"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from contextlib import closing
import sqlite3

BEIJING = timezone(timedelta(hours=8))


class DailyImportWeight:
    @staticmethod
    def sequence(plan):
        plan = str(plan).strip().lower()
        if plan == 'prolite':
            return 'prolite', 100
        if plan == 'pro':
            return 'pro', 50
        raise ValueError('unsupported_import_weight_plan')

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
        cls.prepare_sequences(path)
        return cls(path)

    @classmethod
    def prepare_sequences(cls, path):
        """部署准备显式执行，旧分配表不重写，运行时不自动迁移"""
        with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=rw', uri=True, timeout=1)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise ValueError('unknown_import_weight_schema')
            db.execute('CREATE TABLE IF NOT EXISTS sequence_assignments ('
                       'account TEXT NOT NULL, slot INTEGER NOT NULL, day TEXT NOT NULL, '
                       "sequence TEXT NOT NULL CHECK(sequence IN ('pro','prolite')), "
                       'ordinal INTEGER NOT NULL CHECK(ordinal > 0), weight INTEGER NOT NULL, '
                       "CHECK(weight BETWEEN 1 AND CASE sequence WHEN 'prolite' THEN 100 ELSE 50 END), "
                       'PRIMARY KEY(account,slot), UNIQUE(day,sequence,ordinal))')

    def reserve(self, account_id, slot, plan='pro'):
        if not isinstance(account_id, str) or not account_id or type(slot) is not int or slot < 1:
            raise ValueError('invalid_import_weight_identity')
        sequence, start = self.sequence(plan)
        # 缺失账本或新表时拒绝分配；已登记的旧流程保留原权重
        with closing(sqlite3.connect(self.path.resolve().as_uri() + '?mode=rw', uri=True, timeout=10)) as db, db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            if db.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise ValueError('unknown_import_weight_schema')
            previous = db.execute('SELECT day, ordinal, weight FROM assignments WHERE account=? AND slot=?',
                                  (account_id, slot)).fetchone()
            if previous:
                day, ordinal, weight = previous
                return {'weight': weight, 'day': day, 'ordinal': ordinal,
                        'timezone': 'Asia/Shanghai', 'sequence': 'legacy', 'start': 100}
            previous = db.execute('SELECT day,sequence,ordinal,weight FROM sequence_assignments '
                                  'WHERE account=? AND slot=?', (account_id, slot)).fetchone()
            if previous:
                day, saved_sequence, ordinal, weight = previous
                if saved_sequence != sequence:
                    raise ValueError('import_weight_sequence_changed')
            else:
                moment = self.clock()
                if moment.tzinfo is None:
                    raise ValueError('weight_clock_requires_timezone')
                day = moment.astimezone(BEIJING).date().isoformat()
                ordinal = db.execute('SELECT COALESCE(MAX(ordinal),0)+1 FROM sequence_assignments '
                                     'WHERE day=? AND sequence=?', (day, sequence)).fetchone()[0]
                weight = max(1, start + 1 - ordinal)
                db.execute('INSERT INTO sequence_assignments VALUES (?,?,?,?,?,?)',
                           (account_id, slot, day, sequence, ordinal, weight))
            return {'weight': weight, 'day': day, 'ordinal': ordinal, 'timezone': 'Asia/Shanghai',
                    'sequence': sequence, 'start': start}
