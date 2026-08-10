//go:build !linux && !darwin

package peercreds

import (
	"context"
	"io"
)

func get(_ context.Context, conn io.Reader) (Info, error) {
	return Info{}, io.EOF
}
