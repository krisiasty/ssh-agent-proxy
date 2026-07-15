package app

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRunDoesNotLogForegroundConfigError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")

	stdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = write
	t.Cleanup(func() {
		os.Stdout = stdout
	})

	runErr := Run(path, true)
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}

	if runErr == nil {
		t.Fatal("Run() error = nil, want a configuration error")
	}
	if len(output) != 0 {
		t.Errorf("Run() logged foreground error %q, want no output", output)
	}
}
