package proxy

import (
	"fmt"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestFormatKeysUsesSingleFieldEntries(t *testing.T) {
	key := &agent.Key{
		Format:  "ssh-test",
		Blob:    []byte("public key"),
		Comment: `work "laptop"`,
	}
	want := fmt.Sprintf("[1] ssh-test\n  - comment: %s\n  - sha256: %s\n  - md5: %s\n",
		strconv.Quote(key.Comment),
		strconv.Quote(ssh.FingerprintSHA256(key)),
		strconv.Quote("MD5:"+ssh.FingerprintLegacyMD5(key)),
	)

	if got := formatKeys([]*agent.Key{key}); got != want {
		t.Errorf("formatKeys() = %q, want %q", got, want)
	}
}
