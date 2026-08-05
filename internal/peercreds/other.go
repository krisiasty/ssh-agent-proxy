//go:build !linux && !darwin

package peercreds

import "io"

func get(conn io.Reader) (Info, error) {
	return Info{}, io.EOF
}
