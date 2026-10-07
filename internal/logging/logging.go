// Package logging builds the zap logger both llavero binaries share.
package logging

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New returns a console logger on stderr. Output goes to the journal under
// systemd and to the terminal otherwise, so it stays human-readable rather
// than JSON. debug enables per-frame transport logs.
func New(debug bool) *zap.Logger {
	level := zapcore.InfoLevel
	if debug {
		level = zapcore.DebugLevel
	}
	enc := zapcore.EncoderConfig{
		TimeKey:          "ts",
		LevelKey:         "level",
		NameKey:          "logger",
		MessageKey:       "msg",
		LineEnding:       zapcore.DefaultLineEnding,
		EncodeTime:       zapcore.TimeEncoderOfLayout("15:04:05.000"),
		EncodeLevel:      zapcore.CapitalLevelEncoder,
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeName:       zapcore.FullNameEncoder,
		ConsoleSeparator: "  ",
	}
	core := zapcore.NewCore(zapcore.NewConsoleEncoder(enc), zapcore.Lock(os.Stderr), level)
	return zap.New(core)
}
