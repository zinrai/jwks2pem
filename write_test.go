package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnchangedKeysRewriteNothing(t *testing.T) {
	keys, err := signingKeys(readFixture(t, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := slotFiles(keys, len(keys)+1)
	dir := t.TempDir()
	if _, err := writeFiles(dir, files); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for i := range files {
		os.Chtimes(slotPath(dir, i), old, old)
	}
	written, err := writeFiles(dir, files)
	if err != nil || len(written) != 0 {
		t.Fatalf("rewrote %v (%v)", written, err)
	}
	for i := range files {
		info, _ := os.Stat(slotPath(dir, i))
		if !info.ModTime().Equal(old) {
			t.Fatalf("%s touched", slotPath(dir, i))
		}
	}
}

func slotPath(dir string, i int) string {
	return filepath.Join(dir, fmt.Sprintf("%d.pem", i+1))
}
