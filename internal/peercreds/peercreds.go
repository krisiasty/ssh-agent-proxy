// Package peercreds reads peer credentials from a Unix-domain socket
// so the server can log who connected.
package peercreds

import "io"

// Info holds the peer credentials extracted from a Unix socket.
type Info struct {
	PID     int32  // process ID, or 0 if unavailable (macOS)
	UID     uint32
	Process string // process name, or empty if unavailable
}

// Get reads peer credentials for the given Unix socket.
// On unsupported platforms or on error it returns a zero Info and io.EOF.
func Get(conn io.Reader) (Info, error) {
	return get(conn)
}
