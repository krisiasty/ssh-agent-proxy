package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
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
	assertIdentityLogs(t, entries, "identity", map[string]identityLogExpectation{
		ssh.FingerprintSHA256(pub): {
			comment: "allowed", algorithm: pub.Type(), keySize: float64(keyBits(pub.Marshal())),
		},
		ssh.FingerprintSHA256(otherPub): {
			comment: "other", algorithm: otherPub.Type(), keySize: float64(keyBits(otherPub.Marshal())),
		},
	}, nil, []string{"operation", "attempt"})
	listSummaryIndex := -1
	for i, entry := range entries {
		if entry["msg"] == "upstream call" && entry["operation"] == "list" {
			listSummaryIndex = i
		}
		if message, _ := entry["msg"].(string); strings.HasPrefix(message, "identity ") &&
			(listSummaryIndex < 0 || i <= listSummaryIndex) {
			t.Error("identity detail was logged before the upstream list summary")
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
		log: log.With(
			"conn", "test-connection", "group", "work",
			"uid", 501, "pid", 1234, "process", "ssh"),
		identityLog: log.With("conn", "test-connection", "group", "work"),
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
		message, _ := entry["msg"].(string)
		switch {
		case message == "list identities":
			summaryIndex = i
			if entry["count"] != float64(2) {
				t.Errorf("identity count = %v, want 2", entry["count"])
			}
		case strings.HasPrefix(message, "group identity "):
			identityIndexes = append(identityIndexes, i)
		}
	}
	if summaryIndex < 0 {
		t.Fatal("list identities summary was not logged")
	}
	if len(identityIndexes) != 2 {
		t.Fatalf("group identity logs = %d, want 2: %v", len(identityIndexes), entries)
	}
	for _, index := range identityIndexes {
		if index <= summaryIndex {
			t.Errorf("identity detail at index %d was logged before summary at index %d", index, summaryIndex)
		}
	}
	assertIdentityLogs(t, entries, "group identity", map[string]identityLogExpectation{
		ssh.FingerprintSHA256(first): {
			comment: "first", algorithm: first.Type(), keySize: float64(keyBits(first.Marshal())),
		},
		ssh.FingerprintSHA256(second): {
			comment: "second", algorithm: second.Type(), keySize: float64(keyBits(second.Marshal())),
		},
	}, map[string]any{"conn": "test-connection", "group": "work"}, []string{"uid", "pid", "process"})
}

func TestInfoLogsClientRequestSummariesOnly(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelInfo}))
	keyring := newTestKeyring(t)
	pub := addAgentKey(t, keyring, "allowed")
	matcher, err := keys.NewMatcher("comment", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	filtered := &filterAgent{
		up:            keyring,
		authorization: newGroupAuthorization("work", []keys.Matcher{matcher}, log),
		group:         "work",
		log:           log.With("conn", "test-connection", "group", "work"),
		identityLog:   log.With("conn", "test-connection", "group", "work"),
	}

	if _, err := filtered.List(); err != nil {
		t.Fatal(err)
	}
	if _, err := filtered.SignWithFlags(pub, []byte("payload"), 0); err != nil {
		t.Fatal(err)
	}

	entries := decodeDebugLogs(t, output.Bytes())
	if len(entries) != 2 {
		t.Fatalf("info logs = %d, want list and sign summaries only: %v", len(entries), entries)
	}
	if entries[0]["level"] != "INFO" || entries[0]["msg"] != "list identities" ||
		entries[0]["group"] != "work" || entries[0]["count"] != float64(1) {
		t.Errorf("list summary = %v", entries[0])
	}
	if entries[1]["level"] != "INFO" || entries[1]["msg"] != "sign" || entries[1]["group"] != "work" ||
		entries[1]["fingerprint"] != ssh.FingerprintSHA256(pub) {
		t.Errorf("sign summary = %v", entries[1])
	}
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

func TestUpstreamCallsStayAtDebugLevel(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelInfo}))
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		if err := clientConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing client connection: %v", err)
		}
		if err := serverConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing server connection: %v", err)
		}
	})
	client := &reconnectClient{log: log}
	client.current.Store(&upstreamConn{client: newTestKeyring(t), conn: clientConn})

	if _, err := client.List(); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Errorf("upstream call emitted info logs: %s", output.String())
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
	if len(entries) != 2 {
		t.Fatalf("config key resolution logs = %d, want warning and summary: %v", len(entries), entries)
	}
	warning := findDebugLog(t, entries, "configured key selector matched no upstream key", "")
	if warning["group"] != "work" || warning["config_index"] != float64(2) || warning["selector_type"] != "sha256" {
		t.Errorf("unmatched selector warning = %v", warning)
	}
	if _, ok := warning["selector_value"]; ok {
		t.Errorf("unmatched selector warning contains selector value: %v", warning)
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

func TestUnmatchedSelectorWarningIsLoggedOnTransitions(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	keyring := newTestKeyring(t)
	matcher, err := keys.NewMatcher("comment", "dynamic")
	if err != nil {
		t.Fatal(err)
	}
	authorization := newGroupAuthorization("work", []keys.Matcher{matcher}, log)

	if _, err := authorization.list(keyring); err != nil {
		t.Fatal(err)
	}
	if _, err := authorization.list(keyring); err != nil {
		t.Fatal(err)
	}
	key := addAgentKey(t, keyring, "dynamic")
	if _, err := authorization.list(keyring); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Remove(key); err != nil {
		t.Fatal(err)
	}
	if _, err := authorization.list(keyring); err != nil {
		t.Fatal(err)
	}

	warnings := 0
	for _, entry := range decodeDebugLogs(t, output.Bytes()) {
		if entry["msg"] == "configured key selector matched no upstream key" {
			warnings++
		}
	}
	if warnings != 2 {
		t.Errorf("unmatched selector warnings = %d, want initial warning and warning after disappearance", warnings)
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

type identityLogExpectation struct {
	comment   string
	algorithm string
	keySize   float64
}

func assertIdentityLogs(
	t *testing.T,
	entries []map[string]any,
	messagePrefix string,
	want map[string]identityLogExpectation,
	requiredAttrs map[string]any,
	forbiddenAttrs []string,
) {
	t.Helper()
	var details []map[string]any
	for _, entry := range entries {
		message, _ := entry["msg"].(string)
		if strings.HasPrefix(message, messagePrefix+" ") {
			details = append(details, entry)
		}
	}
	if len(details) != len(want) {
		t.Fatalf("%s logs = %d, want %d: %v", messagePrefix, len(details), len(want), entries)
	}

	got := make(map[string]bool)
	for i, entry := range details {
		wantMessage := fmt.Sprintf("%s %d/%d", messagePrefix, i+1, len(details))
		if entry["msg"] != wantMessage {
			t.Errorf("identity message = %v, want %q", entry["msg"], wantMessage)
		}
		fingerprint, ok := entry["fingerprint"].(string)
		if !ok {
			t.Errorf("%s fingerprint = %v, want string", messagePrefix, entry["fingerprint"])
			continue
		}
		expected, ok := want[fingerprint]
		if !ok {
			t.Errorf("%s has unexpected fingerprint %s", messagePrefix, fingerprint)
			continue
		}
		got[fingerprint] = true
		if entry["comment"] != expected.comment || entry["algorithm"] != expected.algorithm || entry["key_size"] != expected.keySize {
			t.Errorf("%s metadata = comment:%v algorithm:%v key_size:%v, want comment:%q algorithm:%q key_size:%v",
				messagePrefix, entry["comment"], entry["algorithm"], entry["key_size"],
				expected.comment, expected.algorithm, expected.keySize)
		}
		for name, value := range requiredAttrs {
			if entry[name] != value {
				t.Errorf("%s %s = %v, want %v", messagePrefix, name, entry[name], value)
			}
		}
		for _, name := range forbiddenAttrs {
			if _, ok := entry[name]; ok {
				t.Errorf("%s unexpectedly contains %s: %v", messagePrefix, name, entry)
			}
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%s fingerprints = %v, want %v", messagePrefix, got, want)
	}
	for fingerprint := range want {
		if !got[fingerprint] {
			t.Errorf("%s missing fingerprint %s", messagePrefix, fingerprint)
		}
	}
}
