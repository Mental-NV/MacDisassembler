"""Owner-private workspace, serialized writers and atomic committed snapshots."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import uuid
from .errors import Error
from .macho import checked_path, read_regular

MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def identity(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def atomic(path, data, force=False, mode=0o600):
    path = Path(path)
    checked_path(path.parent, directory=True)
    if path.is_symlink():
        raise Error('symlink', 'Output must not be a symlink')
    if path.exists() and not force:
        raise Error('output_exists', 'Output exists; use --force to replace', 8)
    fd, tmp = tempfile.mkstemp(prefix='.macscope-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)  # atomic no-replace publication
            os.unlink(tmp)
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except FileExistsError as e:
        raise Error('output_exists', 'Output appeared during publication', 8) from e
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_json(path, value, force=False, mode=0o600):
    atomic(path, canonical(value)+b'\n', force, mode)


class Project:
    def __init__(self, path):
        self.path = checked_path(path, directory=True)
        if self.path.stat().st_uid != os.getuid() or self.path.stat().st_mode & 0o077:
            raise Error('workspace_permissions', 'Workspace must be owner-private (chmod 700)', 8)
        manifest = json.loads(read_regular(self.path/'project.json', 65536))
        if manifest.get('schema_version') != '1.0':
            raise Error('workspace_schema', 'Unsupported workspace schema; export with its original version', 3)
        self.project_id = manifest['project_id']
        for d in ('inputs', 'engine', 'snapshots', 'jobs', 'home', 'tmp'):
            checked_path(self.path/d, directory=True)
        checked_path(self.path/'index.sqlite')

    @classmethod
    def create(cls, path):
        p = Path(os.path.abspath(path))
        checked_path(p.parent, directory=True)
        try:
            p.mkdir(mode=0o700)
        except FileExistsError as e:
            raise Error('workspace_exists', 'Project path already exists', 8) from e
        for d in ('inputs', 'engine', 'snapshots', 'jobs', 'home', 'tmp'):
            (p/d).mkdir(mode=0o700)
        write_json(p/'project.json', {'schema_version':'1.0', 'project_id':uuid.uuid4().hex})
        with contextlib.closing(sqlite3.connect(p/'index.sqlite')) as db:
            db.executescript('CREATE TABLE images(id TEXT PRIMARY KEY, arch TEXT NOT NULL, metadata TEXT NOT NULL, imported INTEGER NOT NULL DEFAULT 0, active_analysis TEXT); CREATE TABLE analyses(id TEXT PRIMARY KEY, image_id TEXT NOT NULL, payload TEXT NOT NULL);')
        os.chmod(p/'index.sqlite', 0o600)
        return cls(p)

    @contextlib.contextmanager
    def db(self, readonly=True):
        uri = (self.path/'index.sqlite').as_uri() + ('?mode=ro' if readonly else '?mode=rw')
        db = sqlite3.connect(uri, uri=True, timeout=0.1)
        try:
            yield db
            if not readonly:
                db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @contextlib.contextmanager
    def writer(self):
        fd = os.open(self.path/'writer.lock', os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as e:
                raise Error('writer_conflict', 'Another project writer holds the lock', 8, retryable=True) from e
            yield
        finally:
            os.close(fd)

    def images(self):
        with self.db() as db:
            return [dict(json.loads(m), imported=bool(i), active_analysis=a) for m,i,a in db.execute('SELECT metadata, imported, active_analysis FROM images ORDER BY arch,id')]

    def select(self, image=None, arch=None):
        rows = [r for r in self.images() if (not image or r['image_id'] == image) and (not arch or r['arch'] == arch)]
        if len(rows) != 1:
            raise Error('image_selector', 'Select exactly one imported image with --image and/or --arch', 2, partial=[{'image_id':r['image_id'],'arch':r['arch']} for r in rows])
        return rows[0]

    def snapshot(self, image):
        aid = image['active_analysis']
        if not aid:
            raise Error('not_analyzed', 'No committed analysis; run analyze first', 3)
        with self.db() as db:
            row = db.execute('SELECT payload FROM analyses WHERE id=? AND image_id=?', (aid,image['image_id'])).fetchone()
        if row is None:
            raise Error('snapshot_missing', 'Committed snapshot is missing')
        record = json.loads(row[0])
        data = read_regular(self.path/'snapshots'/(aid+'.json'), MAX_SNAPSHOT_BYTES)
        if hashlib.sha256(data).hexdigest() != record['snapshot_sha256']:
            raise Error('snapshot_integrity', 'Snapshot digest mismatch')
        return json.loads(data), record
