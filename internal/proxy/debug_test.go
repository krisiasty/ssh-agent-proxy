package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"testing"

	"github.com/krisiasty/ssh-agent-proxy/internal/keys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestUpstreamCallsAreLogged(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	pub := addAgentKey(t, keyring, "allowed")
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		if err := clientConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing client connection: %v", err)
		}
		if err := serverConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing server connection: %v", err)
		}
	})
	rc := &reconnectClient{log: log}
	rc.current.Store(&upstreamConn{client: keyring, conn: clientConn})

	listed, err := rc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("List() returned %d keys, want 1", len(listed))
	}
	if _, err := rc.SignWithFlags(pub, []byte("payload"), 0); err != nil {
		t.Fatal(err)
	}

	entries := decodeDebugLogs(t, output.Bytes())
	listStarted := findDebugLog(t, entries, "upstream call started", "list")
	if listStarted["attempt"] != float64(1) {
		t.Errorf("list attempt = %v, want 1", listStarted["attempt"])
	}
	listFinished := findDebugLog(t, entries, "upstream call finished", "list")
	if listFinished["keys"] != float64(1) {
		t.Errorf("listed keys = %v, want 1", listFinished["keys"])
	}
	if _, ok := listFinished["duration"].(string); !ok {
		t.Errorf("list duration = %v, want string", listFinished["duration"])
	}

	signStarted := findDebugLog(t, entries, "upstream call started", "sign-with-flags")
	if signStarted["fingerprint"] != ssh.FingerprintSHA256(pub) {
		t.Errorf("sign fingerprint = %v, want %s", signStarted["fingerprint"], ssh.FingerprintSHA256(pub))
	}
	if signStarted["payload_bytes"] != float64(len("payload")) {
		t.Errorf("sign payload_bytes = %v, want %d", signStarted["payload_bytes"], len("payload"))
	}
	if _, ok := signStarted["payload"]; ok {
		t.Errorf("sign log contains payload contents: %v", signStarted)
	}
	findDebugLog(t, entries, "upstream call finished", "sign-with-flags")
}

func TestConfigKeyResolutionIsLogged(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	allowed := addAgentKey(t, keyring, "allowed")
	addAgentKey(t, keyring, "hidden")
	commentMatcher, err := keys.NewMatcher("comment", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	missingMatcher, err := keys.NewMatcher("sha256", "SHA256:not-loaded")
	if err != nil {
		t.Fatal(err)
	}
	authorization := newGroupAuthorization("work", []keys.Matcher{commentMatcher, missingMatcher}, log)

	visible, err := authorization.list(keyring)
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 {
		t.Fatalf("resolved keys = %d, want 1", len(visible))
	}

	entries := decodeDebugLogs(t, output.Bytes())
	resolvedEntries := filterDebugLogs(entries, "config key resolved")
	if len(resolvedEntries) != 2 {
		t.Fatalf("config key resolution logs = %d, want 2: %v", len(resolvedEntries), entries)
	}
	first := resolvedEntries[0]
	if first["group"] != "work" || first["trigger"] != "client-list" || first["config_index"] != float64(1) ||
		first["selector_type"] != "comment" || first["selector_value"] != "allowed" ||
		first["matches"] != float64(1) {
		t.Errorf("first resolution log = %v, want matching comment selector", first)
	}
	fingerprints, ok := first["fingerprints"].([]any)
	if !ok || len(fingerprints) != 1 || fingerprints[0] != ssh.FingerprintSHA256(allowed) {
		t.Errorf("resolved fingerprints = %v, want %s", first["fingerprints"], ssh.FingerprintSHA256(allowed))
	}
	second := resolvedEntries[1]
	if second["config_index"] != float64(2) || second["selector_type"] != "sha256" ||
		second["selector_value"] != "SHA256:not-loaded" || second["matches"] != float64(0) {
		t.Errorf("second resolution log = %v, want unmatched SHA256 selector", second)
	}

	summary := findDebugLog(t, entries, "config keys resolved", "")
	if summary["trigger"] != "client-list" || summary["configured_keys"] != float64(2) || summary["upstream_keys"] != float64(2) ||
		summary["resolved_keys"] != float64(1) {
		t.Errorf("resolution summary = %v, want 2 configured, 2 upstream, 1 resolved", summary)
	}
}

func decodeDebugLogs(t *testing.T, output []byte) []map[string]any {
	t.Helper()
	var entries []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var entry map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("decoding debug log %q: %v", scanner.Bytes(), err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanning debug logs: %v", err)
	}
	return entries
}

func findDebugLog(t *testing.T, entries []map[string]any, message, operation string) map[string]any {
	t.Helper()
	for _, entry := range entries {
		if entry["msg"] == message && (operation == "" || entry["operation"] == operation) {
			return entry
		}
	}
	t.Fatalf("debug log msg=%q operation=%q not found in %v", message, operation, entries)
	return nil
}

func filterDebugLogs(entries []map[string]any, message string) []map[string]any {
	var filtered []map[string]any
	for _, entry := range entries {
		if entry["msg"] == message {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
