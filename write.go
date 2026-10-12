package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Only changed files, not all of them: whatever watches the directory, such
// as a systemd path unit that reloads the verifier, then fires only when a
// key really changed. Through a rename, not written in place: a reader never
// sees half a file.
func writeFiles(dir string, files [][]byte) ([]string, error) {
	var written []string
	for i, data := range files {
		path := filepath.Join(dir, fmt.Sprintf("%d.pem", i+1))
		if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
			continue
		}
		if err := replace(path, data); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

func replace(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".jwks2pem-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
