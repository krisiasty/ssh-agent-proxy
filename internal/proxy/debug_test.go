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
	otherPub := addAgentKey(t, keyring, "other")
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
	if len(listed) != 2 {
		t.Fatalf("List() returned %d keys, want 2", len(listed))
	}
	if _, err := rc.SignWithFlags(pub, []byte("payload"), 0); err != nil {
		t.Fatal(err)
	}

	entries := decodeDebugLogs(t, output.Bytes())
	if len(entries) != 4 {
		t.Fatalf("upstream logs = %d, want 4: %v", len(entries), entries)
	}
	listCall := findDebugLog(t, entries, "upstream call", "list")
	if listCall["attempt"] != float64(1) {
		t.Errorf("list attempt = %v, want 1", listCall["attempt"])
	}
	if listCall["keys"] != float64(2) {
		t.Errorf("listed keys = %v, want 2", listCall["keys"])
	}
	if _, ok := listCall["duration"].(string); !ok {
		t.Errorf("list duration = %v, want string", listCall["duration"])
	}
	assertIdentityLogs(t, entries, "upstream identity", map[string]bool{
		ssh.FingerprintSHA256(pub):      true,
		ssh.FingerprintSHA256(otherPub): true,
	}, "operation", "list", "attempt", float64(1))
	listSummaryIndex := -1
	for i, entry := range entries {
		if entry["msg"] == "upstream call" && entry["operation"] == "list" {
			listSummaryIndex = i
		}
		if entry["msg"] == "upstream identity" && (listSummaryIndex < 0 || i <= listSummaryIndex) {
			t.Error("upstream identity was logged before the upstream list summary")
		}
	}

	signCall := findDebugLog(t, entries, "upstream call", "sign-with-flags")
	if signCall["fingerprint"] != ssh.FingerprintSHA256(pub) {
		t.Errorf("sign fingerprint = %v, want %s", signCall["fingerprint"], ssh.FingerprintSHA256(pub))
	}
	if signCall["payload_bytes"] != float64(len("payload")) {
		t.Errorf("sign payload_bytes = %v, want %d", signCall["payload_bytes"], len("payload"))
	}
	if _, ok := signCall["payload"]; ok {
		t.Errorf("sign log contains payload contents: %v", signCall)
	}
}

func TestClientListLogsEachReturnedIdentity(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	keyring := newTestKeyring(t)
	first := addAgentKey(t, keyring, "first")
	second := addAgentKey(t, keyring, "second")
	firstMatcher, err := keys.NewMatcher("comment", "first")
	if err != nil {
		t.Fatal(err)
	}
	secondMatcher, err := keys.NewMatcher("comment", "second")
	if err != nil {
		t.Fatal(err)
	}
	filtered := &filterAgent{
		up:            keyring,
		authorization: newGroupAuthorization("work", []keys.Matcher{firstMatcher, secondMatcher}, log),
		group:         "work",
		log:           log.With("conn", "test-connection", "group", "work"),
	}

	listed, err := filtered.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("List() returned %d keys, want 2", len(listed))
	}

	entries := decodeDebugLogs(t, output.Bytes())
	summaryIndex := -1
	identityIndexes := make([]int, 0, 2)
	for i, entry := range entries {
		switch entry["msg"] {
		case "list identities":
			summaryIndex = i
			if entry["count"] != float64(2) {
				t.Errorf("identity count = %v, want 2", entry["count"])
			}
		case "list identity":
			identityIndexes = append(identityIndexes, i)
		}
	}
	if summaryIndex < 0 {
		t.Fatal("list identities summary was not logged")
	}
	if len(identityIndexes) != 2 {
		t.Fatalf("list identity logs = %d, want 2: %v", len(identityIndexes), entries)
	}
	for _, index := range identityIndexes {
		if index <= summaryIndex {
			t.Errorf("identity detail at index %d was logged before summary at index %d", index, summaryIndex)
		}
	}
	assertIdentityLogs(t, entries, "list identity", map[string]bool{
		ssh.FingerprintSHA256(first):  true,
		ssh.FingerprintSHA256(second): true,
	}, "conn", "test-connection", "group", "work")
}

func TestFailedUpstreamCallIsLoggedOnce(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	call := beginUpstreamCall(t.Context(), log, "list", "attempt", 1)
	call.finish(errors.New("upstream locked"), "keys", 0)

	entries := decodeDebugLogs(t, output.Bytes())
	if len(entries) != 1 {
		t.Fatalf("upstream call logs = %d, want 1: %v", len(entries), entries)
	}
	entry := findDebugLog(t, entries, "upstream call", "list")
	if entry["err"] != "upstream locked" {
		t.Errorf("upstream error = %v, want upstream locked", entry["err"])
	}
	if entry["keys"] != float64(0) {
		t.Errorf("listed keys = %v, want 0", entry["keys"])
	}
}

func TestConfigKeyResolutionIsLogged(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	addAgentKey(t, keyring, "allowed")
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
	if len(entries) != 1 {
		t.Fatalf("config key resolution logs = %d, want 1: %v", len(entries), entries)
	}
	summary := findDebugLog(t, entries, "config keys resolved", "")
	if summary["trigger"] != "client-list" || summary["configured_keys"] != float64(2) || summary["upstream_keys"] != float64(2) ||
		summary["resolved_keys"] != float64(1) {
		t.Errorf("resolution summary = %v, want 2 configured, 2 upstream, 1 resolved", summary)
	}
	if _, ok := summary["fingerprints"]; ok {
		t.Errorf("resolution summary contains fingerprints: %v", summary)
	}
	if _, ok := summary["resolutions"]; ok {
		t.Errorf("resolution summary contains selector details: %v", summary)
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

func assertIdentityLogs(t *testing.T, entries []map[string]any, message string, want map[string]bool, attrs ...any) {
	t.Helper()
	got := make(map[string]bool)
	for _, entry := range entries {
		if entry["msg"] != message {
			continue
		}
		fingerprint, ok := entry["fingerprint"].(string)
		if !ok {
			t.Errorf("%s fingerprint = %v, want string", message, entry["fingerprint"])
			continue
		}
		got[fingerprint] = true
		for i := 0; i < len(attrs); i += 2 {
			name := attrs[i].(string)
			if entry[name] != attrs[i+1] {
				t.Errorf("%s %s = %v, want %v", message, name, entry[name], attrs[i+1])
			}
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%s fingerprints = %v, want %v", message, got, want)
	}
	for fingerprint := range want {
		if !got[fingerprint] {
			t.Errorf("%s missing fingerprint %s", message, fingerprint)
		}
	}
}
