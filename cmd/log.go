package cmd

import (
	colorable "github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log levels
const (
	DebugLevel = zapcore.DebugLevel
	InfoLevel  = zapcore.InfoLevel
)

// Global logger and level
var (
	Level  = zap.NewAtomicLevelAt(InfoLevel)
	Logger = New(Level)
)

// New logger
func New(level zap.AtomicLevel) *zap.Logger {

	ec := zap.NewDevelopmentEncoderConfig()
	ec.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(ec),
		zapcore.AddSync(colorable.NewColorableStdout()),
		level,
	))

	return logger
}
