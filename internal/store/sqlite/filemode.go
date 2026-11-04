package sqlite

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// dbFileMode is the mode a new database file is created with. The database
// holds user passwords, actor keys and data bags, so it is owner-only.
const dbFileMode = 0o600

// sidecarSuffixes are the files SQLite keeps next to the database. It creates
// them with the database file's permissions, so a private database gives
// private sidecars; existing ones are tightened in case an older version left
// them readable.
var sidecarSuffixes = []string{"-wal", "-shm", "-journal"}

// securePath makes the database at path owner-only before SQLite opens it.
// A missing database is created empty with dbFileMode, because SQLite's own
// default is 0644 (less the umask). An existing database and its sidecars
// have their group and other permission bits removed. Permissions are only
// ever removed, never added. In-memory databases and "file:" URIs are left to
// SQLite.
func securePath(path string) error {
	if isMemory(path) || strings.HasPrefix(path, "file:") {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, dbFileMode)
	if err != nil {
		return fmt.Errorf("open database %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("open database %s: %w", path, err)
	}
	for _, p := range append([]string{path}, sidecarPaths(path)...) {
		if err := stripGroupOther(p); err != nil {
			return err
		}
	}
	return nil
}

func sidecarPaths(path string) []string {
	out := make([]string, 0, len(sidecarSuffixes))
	for _, s := range sidecarSuffixes {
		out = append(out, path+s)
	}
	return out
}

// stripGroupOther removes the group and other permission bits from p, if it
// exists and has any.
func stripGroupOther(p string) error {
	fi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", p, err)
	}
	mode := fi.Mode().Perm()
	if mode&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(p, mode&^0o077); err != nil {
		return fmt.Errorf("restrict permissions of %s to its owner: %w", p, err)
	}
	return nil
}
