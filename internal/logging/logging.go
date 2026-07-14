// Package logging configures the slog logger used across the tool.
package logging

import (
	"log/slog"
	"os"
)

// Setup returns a slog.Logger writing to stdout.
//
// In foreground mode this is what the user sees directly. As a managed service
// stdout is captured by the platform: the systemd journal on Linux, and the
// launchd log file on macOS.
func Setup(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}
