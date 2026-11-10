"""Owner-private workspace, serialized writers and atomic committed snapshots."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid
from .errors import Error
from .macho import checked_path, open_directory, read_regular

MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r'[0-9a-f]{64}')
WORKSPACE_DIRECTORIES = ('inputs', 'engine', 'snapshots', 'jobs', 'home', 'tmp')
WORKSPACE_RESERVED = frozenset((*WORKSPACE_DIRECTORIES, 'project.json', 'writer.lock',
                                'index.sqlite', 'index.sqlite-journal', 'index.sqlite-wal', 'index.sqlite-shm'))
CANONICAL_JSON = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def canonical(value):
    return CANONICAL_JSON.encode(value).encode()


def canonical_chunks(value):
    for part in CANONICAL_JSON.iterencode(value):
        yield part.encode()


def identity(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def is_digest(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def json_object(payload, code, message):
    try:
        value = json.loads(payload)
    except (TypeError, ValueError, RecursionError) as error:
        raise Error(code, message) from error
    if not isinstance(value, dict):
        raise Error(code, message)
    return value


def output_directory_matches(parent, directory):
    try:
        current = open_directory(parent)
        try:
            return os.path.samestat(os.fstat(directory), os.fstat(current))
        finally:
            os.close(current)
    except OSError:
        return False


def check_output_entry(directory, name, force):
    try:
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(current.st_mode):
        raise Error('symlink', 'Output must not be a symlink')
    if not force:
        raise Error('output_exists', 'Output exists; use --force to replace', 8)


def atomic(path, data, force=False, mode=0o600):
    atomic_chunks(path, (data,), force, mode)


def atomic_chunks(path, chunks, force=False, mode=0o600):
    path = Path(os.path.abspath(path))
    parent = checked_path(path.parent, directory=True)
    try:
        directory = open_directory(parent)
    except OSError as error:
        raise Error('output_directory_changed', 'Output directory changed before publication', 8) from error
    try:
        check_output_entry(directory, path.name, force)
        tmp = '.macscope-' + uuid.uuid4().hex
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), mode)
                stream.writelines(chunks)
                stream.flush()
                os.fsync(stream.fileno())
            if not output_directory_matches(parent, directory):
                raise Error('output_directory_changed', 'Output directory changed before publication', 8)
            if force:
                check_output_entry(directory, path.name, force)
                os.replace(tmp, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            else:
                os.link(tmp, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except FileExistsError as error:
            raise Error('output_exists', 'Output appeared during publication', 8) from error
        finally:
            try:
                os.unlink(tmp, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.fsync(directory)
        if not output_directory_matches(parent, directory):
            raise Error('output_directory_changed', 'Output was published in the original directory, but its path changed',
                        8, partial={'published_in_original_directory': True})
    finally:
        os.close(directory)


def write_json(path, value, force=False, mode=0o600):
    atomic(path, canonical(value)+b'\n', force, mode)


class Project:
    def __init__(self, path):
        self.path = checked_path(path, directory=True)
        if self.path.stat().st_uid != os.getuid() or self.path.stat().st_mode & 0o077:
            raise Error('workspace_permissions', 'Workspace must be owner-private (chmod 700)', 8)
        try:
            manifest = json.loads(read_regular(self.path/'project.json', 65536))
        except (ValueError, RecursionError) as error:
            raise Error('workspace_manifest', 'Invalid workspace manifest JSON') from error
        if not isinstance(manifest, dict) or not isinstance(manifest.get('schema_version'), str):
            raise Error('workspace_manifest', 'Invalid workspace manifest structure')
        if manifest['schema_version'] != '1.0':
            raise Error('workspace_schema', 'Unsupported workspace schema; export with its original version', 3)
        project_id = manifest.get('project_id')
        if not isinstance(project_id, str) or not re.fullmatch(r'[a-f0-9]{32}', project_id):
            raise Error('workspace_manifest', 'Invalid workspace identifier')
        self.project_id = project_id
        for d in WORKSPACE_DIRECTORIES:
            checked_path(self.path/d, directory=True)
        checked_path(self.path/'index.sqlite')
        try:
            with self.db() as db:
                tables = db.execute("SELECT name FROM sqlite_schema WHERE type='table' "
                                    "AND name IN ('images','analyses')").fetchall()
                if len(tables) != 2:
                    raise Error('workspace_index', 'Workspace index is missing a required table')
                db.execute('SELECT id,arch,metadata,imported,active_analysis FROM images LIMIT 0')
                db.execute('SELECT id,image_id,payload FROM analyses LIMIT 0')
        except sqlite3.DatabaseError as error:
            if getattr(error, 'sqlite_errorcode', 0) & 0xff in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise Error('workspace_index_busy', 'Workspace index is locked', 8, retryable=True) from error
            raise Error('workspace_index', 'Workspace index cannot open the supported schema') from error

    @classmethod
    def create(cls, path):
        p = Path(os.path.abspath(path))
        checked_path(p.parent, directory=True)
        try:
            p.mkdir(mode=0o700)
        except FileExistsError as e:
            raise Error('workspace_exists', 'Project path already exists', 8) from e
        for d in WORKSPACE_DIRECTORIES:
            (p/d).mkdir(mode=0o700)
        write_json(p/'project.json', {'schema_version':'1.0', 'project_id':uuid.uuid4().hex})
        with contextlib.closing(sqlite3.connect(p/'index.sqlite')) as db:
            db.executescript('CREATE TABLE images(id TEXT PRIMARY KEY, arch TEXT NOT NULL, metadata TEXT NOT NULL, imported INTEGER NOT NULL DEFAULT 0, active_analysis TEXT); CREATE TABLE analyses(id TEXT PRIMARY KEY, image_id TEXT NOT NULL, payload TEXT NOT NULL);')
        os.chmod(p/'index.sqlite', 0o600)
        return cls(p)

    @contextlib.contextmanager
    def db(self, readonly=True):
        uri = (self.path/'index.sqlite').as_uri() + ('?mode=ro' if readonly else '?mode=rw')
        try:
            with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=0.1)) as db:
                try:
                    yield db
                    if not readonly:
                        db.commit()
                except BaseException:
                    db.rollback()
                    raise
        except sqlite3.DatabaseError as error:
            code = getattr(error, 'sqlite_errorcode', 0)
            if code & 0xff in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB):
                raise Error('workspace_index', 'Workspace index is corrupt') from error
            if not code and isinstance(error, sqlite3.OperationalError):
                raise Error('workspace_index', 'Workspace index contains unreadable data') from error
            raise

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
            images = []
            rows = db.execute('SELECT id,arch,metadata,imported,active_analysis FROM images ORDER BY arch,id')
            for image_id, arch, payload, imported, aid in rows:
                image = json_object(payload, 'workspace_image', 'Invalid image metadata in the workspace index')
                if (not is_digest(image_id) or arch not in ('arm64', 'x86_64')
                        or image.get('image_id') != image_id or image.get('arch') != arch
                        or not all(is_digest(image.get(key)) for key in ('sha256', 'artifact_sha256'))
                        or type(imported) is not int or imported not in (0, 1)
                        or (aid is not None and not is_digest(aid))):
                    raise Error('workspace_image', 'Image metadata or analysis identity disagrees with the workspace index')
                images.append(dict(image, imported=bool(imported), active_analysis=aid))
            return images

    def select(self, image=None, arch=None):
        rows = [r for r in self.images() if (not image or r['image_id'] == image) and (not arch or r['arch'] == arch)]
        if len(rows) != 1:
            raise Error('image_selector', 'Select exactly one imported image with --image and/or --arch', 2, partial=[{'image_id':r['image_id'],'arch':r['arch']} for r in rows])
        return rows[0]

    def snapshot(self, image):
        aid = image['active_analysis']
        if aid is None:
            raise Error('not_analyzed', 'No committed analysis; run analyze first', 3)
        if not is_digest(aid) or not is_digest(image.get('image_id')):
            raise Error('snapshot_identity', 'Invalid analysis or image identity for the saved snapshot')
        with self.db() as db:
            row = db.execute('SELECT payload FROM analyses WHERE id=? AND image_id=?', (aid,image['image_id'])).fetchone()
        if row is None:
            raise Error('snapshot_missing', 'Committed snapshot is missing')
        record = json_object(row[0], 'snapshot_record', 'Invalid saved analysis record in the workspace index')
        if not is_digest(record.get('snapshot_sha256')):
            raise Error('snapshot_record', 'Saved analysis record has no valid snapshot digest')
        data = read_regular(self.path/'snapshots'/(aid+'.json'), MAX_SNAPSHOT_BYTES)
        if hashlib.sha256(data).hexdigest() != record['snapshot_sha256']:
            raise Error('snapshot_integrity', 'Snapshot digest mismatch')
        snapshot = json_object(data, 'snapshot_format', 'Invalid saved analysis snapshot JSON')
        if (not isinstance(snapshot.get('functions'), list)
                or any(not isinstance(function, dict) for function in snapshot['functions'])
                or not isinstance(snapshot.get('engine'), dict)
                or snapshot.get('status') not in ('complete', 'partial')):
            raise Error('snapshot_format', 'Saved snapshot has invalid analysis fields')
        stored_image = snapshot.get('image')
        if (snapshot.get('analysis_id') != aid or not isinstance(stored_image, dict)
                or any(stored_image.get(key) != image.get(key)
                       for key in ('image_id', 'arch', 'sha256', 'artifact_sha256'))):
            raise Error('snapshot_identity', 'Saved snapshot belongs to a different analysis or image')
        return snapshot, record
