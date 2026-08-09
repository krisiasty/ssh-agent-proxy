package logging

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNewLoggerWritesOneJSONObjectPerLine(t *testing.T) {
	var output bytes.Buffer
	logger := newLogger(&output, false)
	logger.Info("line one\nline two", "path", "/tmp/path with spaces", "groups", 2)

	if got := bytes.Count(output.Bytes(), []byte{'\n'}); got != 1 {
		t.Fatalf("logger wrote %d newline characters, want 1: %q", got, output.Bytes())
	}
	entry := decodeLogEntry(t, output.Bytes())
	if entry["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", entry["level"])
	}
	if entry["msg"] != "line one\nline two" {
		t.Errorf("msg = %v, want multiline message", entry["msg"])
	}
	if entry["path"] != "/tmp/path with spaces" {
		t.Errorf("path = %v, want structured path", entry["path"])
	}
	if entry["groups"] != float64(2) {
		t.Errorf("groups = %v, want 2", entry["groups"])
	}
	if _, ok := entry["time"].(string); !ok {
		t.Errorf("time = %v, want a JSON string", entry["time"])
	}
}

func TestNewLoggerHonorsDebugLevel(t *testing.T) {
	var infoOutput bytes.Buffer
	newLogger(&infoOutput, false).Debug("hidden")
	if infoOutput.Len() != 0 {
		t.Errorf("non-debug logger wrote %q, want no output", infoOutput.Bytes())
	}

	var debugOutput bytes.Buffer
	newLogger(&debugOutput, true).Debug("visible")
	entry := decodeLogEntry(t, debugOutput.Bytes())
	if entry["level"] != "DEBUG" || entry["msg"] != "visible" {
		t.Errorf("debug entry = %v, want DEBUG visible", entry)
	}
}

func TestRedirectOutputWritesJSON(t *testing.T) {
	var output bytes.Buffer
	redirect := &redirectOutput{log: newLogger(&output, false)}
	message := []byte("legacy failure\n")

	written, err := redirect.Write(message)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(message) {
		t.Errorf("Write() = %d, want %d", written, len(message))
	}
	entry := decodeLogEntry(t, output.Bytes())
	if entry["level"] != "WARN" || entry["msg"] != "legacy failure" {
		t.Errorf("legacy entry = %v, want WARN legacy failure", entry)
	}
}

func decodeLogEntry(t *testing.T, line []byte) map[string]any {
	t.Helper()
	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		t.Fatalf("decoding log entry %q: %v", line, err)
	}
	return entry
}
