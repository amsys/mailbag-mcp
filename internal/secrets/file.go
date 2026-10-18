// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FileStore keeps secrets in plain files, one file for each key, in
// one directory. It is the fallback for a desktop with no keyring
// (D4, D13). Each write goes to a temporary file in the same
// directory, then a rename, so a reader never sees a half-written
// file and two writers for different keys never step on each other
// (trap A10).
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
type FileStore struct {
	dir string
}

// NewFileStore returns a FileStore rooted at dir. dir is created with
// mode 0700 on the first Set.
func NewFileStore(dir string) *FileStore {
	return &FileStore{dir: dir}
}

// Kind returns "file".
func (s *FileStore) Kind() string { return KindFile }

// keyPath returns the file that holds key. It refuses a key that
// would leave dir. Account aliases already pass the pattern of B17
// before they reach here, but this store never trusts that alone --
// a key is written into a file path, which is exactly the boundary
// B17 exists to guard.
func (s *FileStore) keyPath(key string) (string, error) {
	if key == "" || strings.ContainsRune(key, filepath.Separator) || strings.Contains(key, "..") {
		return "", fmt.Errorf("secrets: invalid key %q", key)
	}
	return filepath.Join(s.dir, key), nil
}

// checkDir refuses a store directory that group or other can write:
// such a user can replace a key file (trap B16). The check is skipped
// on Windows, which has no such bits, and when dir does not exist yet.
func (s *FileStore) checkDir() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(s.dir)
	if err != nil {
		return nil
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("secrets: %s has mode %#o, writable by group or other; fix its permissions (chmod 700) and try again", s.dir, info.Mode().Perm())
	}
	return nil
}

// Get reads key. It refuses a file whose mode grants any permission
// to group or other, and a directory that group or other can write
// (trap B16); the checks are skipped on Windows, which has no such
// bits.
func (s *FileStore) Get(key string) (string, error) {
	path, err := s.keyPath(key)
	if err != nil {
		return "", err
	}
	if err := s.checkDir(); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("secrets: stat %s: %w", path, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("secrets: %s has mode %#o, readable by group or other; fix its permissions (chmod 600) and try again", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: keyPath rejects separators and ".." in the key, so path stays inside the store dir
	if err != nil {
		return "", fmt.Errorf("secrets: read %s: %w", path, err)
	}
	return string(data), nil
}

// Set writes key with a temporary file and a rename, so a reader
// never sees a partial write and a crash mid-write leaves the old
// value in place (trap A10, B16).
func (s *FileStore) Set(key, value string) error {
	path, err := s.keyPath(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("secrets: create %s: %w", s.dir, err)
	}
	if err := s.checkDir(); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(s.dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("secrets: create temp file in %s: %w", s.dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if _, err := tmp.WriteString(value); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secrets: write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secrets: chmod %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secrets: sync %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("secrets: close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("secrets: rename %s to %s: %w", tmpPath, path, err)
	}
	return nil
}

// Delete removes key.
func (s *FileStore) Delete(key string) error {
	path, err := s.keyPath(key)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("secrets: remove %s: %w", path, err)
	}
	return nil
}
