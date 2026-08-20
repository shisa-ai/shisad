# SQLite FTS5 Runtime

shisad uses Python's standard `sqlite3` module for local memory and retrieval
storage. Retrieval works best when that Python module is linked against SQLite
with FTS5 enabled. If FTS5 is missing, shisad falls back to degraded lexical
search instead of failing startup, but operators should prefer a runtime with
FTS5.

SQLite documents FTS5 as a virtual table module and describes enabling it with
the SQLite `--enable-fts5` configure option or the `SQLITE_ENABLE_FTS5`
preprocessor symbol. Python's `sqlite3` module reports the runtime SQLite
library version through `sqlite3.sqlite_version`.

## Schema Versions and Recovery

shisad owns four mutable SQLite databases: channel replay, channel delivery,
shared memory, and timeline. Each physical database has one schema-version
authority. All four currently admit version `1`. Replay and delivery retain
strict admission; they do not have a legacy migration. Memory and timeline can
migrate only a structurally recognized version-0 schema.

Before a memory or timeline migration changes the database, shisad checkpoints
its WAL, creates an exact `<database>.pre-v1.bak`, validates the copy and its
version, and tightens its permissions where the platform supports that. The
schema change and `PRAGMA user_version = 1` then commit in one native SQLite
transaction. A retry reuses the copy only when it still exactly matches the
legacy database.

To inspect a stopped database without changing it, substitute its exact path:

```bash
python - <<'PY' /absolute/path/to/database.sqlite3
import sqlite3
import sys

uri = f"file:{sys.argv[1]}?mode=ro"
with sqlite3.connect(uri, uri=True) as conn:
    print("user_version:", conn.execute("PRAGMA user_version").fetchone()[0])
    print("quick_check:", conn.execute("PRAGMA quick_check").fetchone()[0])
PY
```

If startup refuses a database, stop the daemon and retain the database, its
`-wal`/`-shm` companions if present, and any `.pre-v1.bak`. Do not delete,
rename, or combine these files while the daemon is running. A newer version is
not safe to downgrade. An unknown, empty, corrupt, or mismatched database needs
operator diagnosis or a trusted complete snapshot; shisad will not overwrite
or reset it.

For rollback immediately after a failed or incompatible version-0 migration,
first preserve the refused current files elsewhere, then copy the matching
`.pre-v1.bak` back to its original database path while the daemon is stopped.
The copy is one database's pre-migration state, not a transactionally
consistent backup of the whole data root. Prefer restoring a complete trusted
data-root snapshot when other state may also have changed.

## Full Data-Root Recovery

For a consistent operator recovery point, stop the daemon and back up the
configured data root as one manifest-verified archive:

```bash
shisad data backup /operator-controlled/shisad-data.shisad-backup
```

This archive includes the memory and timeline databases, their safe in-root
companions, and all other regular files and directories under the data root.
It excludes the root `.shisad.lock` and every path outside the root. A symlink
or special file causes the whole operation to refuse. The archive is owner-only
where supported and is not encrypted, so store it as sensitive data.

Restore never replaces or merges an active root. Keep the old root, stop the
daemon, and name an absent or empty destination explicitly:

```bash
shisad data restore /operator-controlled/shisad-data.shisad-backup \
  --destination /absolute/path/to/restored-data
```

The command verifies the complete manifest, member set, sizes, and SHA-256
digests before creating payload files. After selecting the restored root in
configuration, run `shisad start`, `shisad status`, and
`shisad doctor check --component storage`. If runtime validation fails, stop
the daemon and restore another verified archive into a new empty destination;
do not combine individual databases or WAL companions across backups.

## Verify

After the daemon starts, check the runtime component:

```bash
uv run shisad doctor check --component storage
```

The preferred state is:

```json
{
  "checks": {
    "storage": {
      "status": "ok",
      "sqlite": {
        "fts5": {
          "available": true
        }
      }
    }
  }
}
```

For an offline check before starting shisad, run the same probe against the
exact Python interpreter or virtual environment that will run shisad:

```bash
python - <<'PY'
import sqlite3

print("sqlite:", sqlite3.sqlite_version)
with sqlite3.connect(":memory:") as conn:
    conn.execute("CREATE VIRTUAL TABLE temp.shisad_fts5_probe USING fts5(content)")
print("fts5: yes")
PY
```

If this raises `sqlite3.OperationalError: no such module: fts5`, that Python
runtime is linked against SQLite without FTS5. Checking the `sqlite3` shell is
not enough; the Python module can be linked against a different SQLite library
than the command-line tool.

## Recommended Runtimes

For source checkouts, run the verification command after `uv sync`. If it fails,
select or build a Python runtime that links against an FTS5-capable SQLite, then
recreate the project virtual environment with that Python.

For package installs, run the offline probe before installing shisad into the
target environment, or run `shisad doctor check --component storage` after the
daemon starts. Missing FTS5 should be treated as degraded and actionable, not as
a reason to disable memory.

For future official containers or packaged runtime images, the image should ship
Python linked against SQLite with FTS5 enabled and should run the offline probe
as a build-time assertion.

## Common OS Paths

### Debian and Ubuntu

Install SQLite headers before building Python from source or through pyenv:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv sqlite3 libsqlite3-dev
```

If you are using distro Python, run the offline probe. If it fails, installing
`libsqlite3-dev` afterward will not relink an already-built Python; rebuild or
select a Python that was built after the SQLite development package was present.

### Fedora, RHEL, and compatible distributions

Install SQLite headers before building Python from source or through pyenv:

```bash
sudo dnf install -y python3 python3-devel sqlite sqlite-devel
```

Then run the offline probe in the exact Python environment used for shisad.

### macOS with Homebrew

Use Homebrew Python where possible, then verify:

```bash
brew install python sqlite
python3 - <<'PY'
import sqlite3

print("sqlite:", sqlite3.sqlite_version)
with sqlite3.connect(":memory:") as conn:
    conn.execute("CREATE VIRTUAL TABLE temp.shisad_fts5_probe USING fts5(content)")
print("fts5: yes")
PY
```

If building Python with pyenv, install Homebrew SQLite first and point the build
at it:

```bash
brew install sqlite
CPPFLAGS="-I$(brew --prefix sqlite)/include" \
LDFLAGS="-L$(brew --prefix sqlite)/lib" \
PKG_CONFIG_PATH="$(brew --prefix sqlite)/lib/pkgconfig" \
pyenv install 3.12
```

After the build, verify with the pyenv-selected Python. The Homebrew `sqlite`
formula is keg-only, so a Python build may otherwise link against macOS system
SQLite.

### Windows

Use the Python runtime that will run shisad and execute the offline probe. If
you run shisad under WSL, follow the Linux guidance for that WSL distribution.
For custom native Python builds, link Python against SQLite built with FTS5 and
verify with the probe before installing shisad.

## Source Builds

If the platform SQLite does not include FTS5, build SQLite with FTS5 enabled and
then build Python against that SQLite installation:

```bash
# Download the latest sqlite-autoconf-*.tar.gz from https://sqlite.org/download.html
tar -xzf sqlite-autoconf-*.tar.gz
cd sqlite-autoconf-*
./configure --prefix=/opt/sqlite --enable-fts5
make
sudo make install
```

Then build Python with compiler and linker flags that point to that SQLite:

```bash
CPPFLAGS="-I/opt/sqlite/include" \
LDFLAGS="-L/opt/sqlite/lib" \
PKG_CONFIG_PATH="/opt/sqlite/lib/pkgconfig" \
./configure --prefix=/opt/python-shisad
make
sudo make install
```

Run the offline probe with `/opt/python-shisad/bin/python3` before creating the
shisad virtual environment.

## References

- SQLite FTS5 documentation: https://sqlite.org/fts5.html
- Python `sqlite3` documentation: https://docs.python.org/3/library/sqlite3.html
- pyenv build guidance: https://github.com/pyenv/pyenv
- Homebrew SQLite formula: https://formulae.brew.sh/formula/sqlite
