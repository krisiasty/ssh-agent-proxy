// Package logging configures the slog logger used across the tool.
package logging

import (
	"bytes"
	"io"
	"log"
	"log/slog"
	"os"
)

// redirectOutput bridges the legacy log package to the slog logger.
//
// agent.ServeAgent uses log.Printf for errors; we redirect those messages
// here so they appear in the same structured stream as everything else.
type redirectOutput struct {
	log *slog.Logger
}

func (r *redirectOutput) Write(p []byte) (int, error) {
	line := bytes.TrimSpace(p)
	r.log.Warn(string(line))
	return len(p), nil
}

// Setup returns a slog.Logger writing JSON Lines to stdout and configures the
// global log package to forward its output through the returned logger.
//
// In foreground mode this is what the user sees directly. As a managed service
// stdout is captured by the platform: the systemd journal on Linux, and the
// launchd log file on macOS.
func Setup(debug bool) *slog.Logger {
	logger := newLogger(os.Stdout, debug)

	// Redirect the legacy log package so messages from agent.ServeAgent
	// flow through slog instead of going directly to stderr.
	log.SetOutput(&redirectOutput{log: logger})
	log.SetFlags(0)

	return logger
}

func newLogger(output io.Writer, debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	h := slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}
