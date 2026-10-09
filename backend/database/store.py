"""SQLite transactions with per-operation sessions and explicit write serialization."""
from contextlib import contextmanager
from threading import RLock
import logging
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from backend.database.models import Base
from backend.errors import APIError

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, url, max_bytes=1073741824):
        if not url.startswith('sqlite:'):
            raise ValueError('Phase 4 supports SQLite only')
        if type(max_bytes) is not int or max_bytes < 1048576:
            raise ValueError('SQLite storage budget must be an integer of at least 1 MiB')
        self.max_bytes = max_bytes
        self.lock = RLock()
        self.engine = create_engine(url, connect_args={'check_same_thread': False, 'timeout': 5},
                                    **({'poolclass': StaticPool} if url in ('sqlite://', 'sqlite:///:memory:') else {}))
        self.initialized = False

        @event.listens_for(self.engine, 'connect')
        def sqlite_setup(connection, _):
            cursor = connection.cursor()
            cursor.execute('PRAGMA foreign_keys=ON')
            cursor.execute('PRAGMA busy_timeout=5000')
            cursor.execute('PRAGMA journal_mode=WAL')
            page_size = cursor.execute('PRAGMA page_size').fetchone()[0]
            current_pages = cursor.execute('PRAGMA page_count').fetchone()[0]
            # Never truncate a preexisting database larger than the configured budget.
            limit_pages = max(current_pages, max_bytes // page_size)
            cursor.execute(f'PRAGMA max_page_count={limit_pages}')
            cursor.execute('PRAGMA wal_autocheckpoint=1000')
            cursor.execute('PRAGMA journal_size_limit=16777216')
            cursor.close()
        try:
            self.initialize()
        except SQLAlchemyError:
            logger.exception('Database initialization failed; API will report database_unavailable')

    def initialize(self):
        if not self.initialized:
            Base.metadata.create_all(self.engine)
            self.initialized = True

    def storage_status(self):
        with self.transaction() as session:
            page_size = session.scalar(text('PRAGMA page_size'))
            pages = session.scalar(text('PRAGMA page_count'))
            maximum = session.scalar(text('PRAGMA max_page_count'))
            return {'usedBytes': pages * page_size, 'limitBytes': maximum * page_size,
                    'configuredBytes': self.max_bytes, 'atCapacity': pages >= maximum}

    @contextmanager
    def transaction(self, write=False):
        with self.lock:
            try:
                self.initialize()
                with Session(self.engine, expire_on_commit=False) as session:
                    if write:
                        # SQLite's write reservation also serializes different
                        # connections/processes before their read-modify-write.
                        session.execute(text('BEGIN IMMEDIATE'))
                    yield session
                    session.commit()
            except IntegrityError as error:
                raise APIError('mapping_conflict', 'This mapping already exists or violates a data constraint.', 409) from error
            except SQLAlchemyError as error:
                logger.exception('Database transaction failed')
                raise APIError('database_unavailable', 'The database is unavailable or its storage limit was reached. No change was committed.', 503) from error
