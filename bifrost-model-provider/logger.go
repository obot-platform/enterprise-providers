package bifrostprovider

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// SlogLogger adapts a *slog.Logger to the schemas.Logger interface.
// Level can be adjusted at runtime via SetLevel; output format can be
// toggled between JSON and text via SetOutputType.
type SlogLogger struct {
	logger *slog.Logger
	level  *slog.LevelVar
	writer *os.File
	attr   slog.Attr
}

var _ schemas.Logger = (*SlogLogger)(nil)

// DefaultLogLevel is the fallback level used by NewSlogLogger when the
// LOG_LEVEL env var is unset or unrecognized. Callers may override this
// (e.g. in main()) to change the default verbosity for a provider binary.
var DefaultLogLevel slog.Level = slog.LevelInfo

// NewSlogLogger returns a SlogLogger that writes JSON to stderr. The level
// is taken from the LOG_LEVEL env var (debug, info, warn, error), falling
// back to DefaultLogLevel. The provider value is attached to every log
// entry under the "provider" key (e.g. "amazon-bedrock-api-key-model-provider").
func NewSlogLogger(provider string) *SlogLogger {
	level := new(slog.LevelVar)
	level.Set(parseLogLevel(os.Getenv("LOG_LEVEL")))
	writer := os.Stderr
	attr := slog.String("provider", provider)
	return &SlogLogger{
		logger: slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: level})).With(attr),
		level:  level,
		writer: writer,
		attr:   attr,
	}
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return DefaultLogLevel
	}
}

func (l *SlogLogger) Debug(msg string, args ...any) {
	msg, args = normalizeArgs(msg, args)
	l.logger.Debug(msg, args...)
}

func (l *SlogLogger) Info(msg string, args ...any) {
	msg, args = normalizeArgs(msg, args)
	l.logger.Info(msg, args...)
}

func (l *SlogLogger) Warn(msg string, args ...any) {
	msg, args = normalizeArgs(msg, args)
	l.logger.Warn(msg, args...)
}

func (l *SlogLogger) Error(msg string, args ...any) {
	msg, args = normalizeArgs(msg, args)
	l.logger.Error(msg, args...)
}

// Fatal logs at error level then exits the process with status 1, matching the
// semantics described in the Bifrost Logger interface.
func (l *SlogLogger) Fatal(msg string, args ...any) {
	msg, args = normalizeArgs(msg, args)
	l.logger.Error(msg, args...)
	os.Exit(1)
}

// normalizeArgs handles callers that use printf-style format strings (Bifrost
// does this) rather than slog's key/value pairs. When msg contains a `%` verb
// and args are present, format the message and return no args.
func normalizeArgs(msg string, args []any) (string, []any) {
	if len(args) > 0 && strings.Contains(msg, "%") {
		return fmt.Sprintf(msg, args...), nil
	}
	return msg, args
}

func (l *SlogLogger) SetLevel(level schemas.LogLevel) {
	if l.level == nil {
		return
	}
	l.level.Set(toSlogLevel(level))
}

func (l *SlogLogger) SetOutputType(outputType schemas.LoggerOutputType) {
	if l.level == nil || l.writer == nil {
		return
	}
	opts := &slog.HandlerOptions{Level: l.level}
	switch outputType {
	case schemas.LoggerOutputTypePretty:
		l.logger = slog.New(slog.NewTextHandler(l.writer, opts)).With(l.attr)
	default:
		l.logger = slog.New(slog.NewJSONHandler(l.writer, opts)).With(l.attr)
	}
}

func (l *SlogLogger) LogHTTPRequest(level schemas.LogLevel, msg string) schemas.LogEventBuilder {
	return &slogEventBuilder{
		logger: l.logger,
		level:  toSlogLevel(level),
		msg:    msg,
	}
}

func toSlogLevel(level schemas.LogLevel) slog.Level {
	switch level {
	case schemas.LogLevelDebug:
		return slog.LevelDebug
	case schemas.LogLevelWarn:
		return slog.LevelWarn
	case schemas.LogLevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type slogEventBuilder struct {
	logger *slog.Logger
	level  slog.Level
	msg    string
	attrs  []slog.Attr
}

func (b *slogEventBuilder) Str(key, val string) schemas.LogEventBuilder {
	b.attrs = append(b.attrs, slog.String(key, val))
	return b
}

func (b *slogEventBuilder) Int(key string, val int) schemas.LogEventBuilder {
	b.attrs = append(b.attrs, slog.Int(key, val))
	return b
}

func (b *slogEventBuilder) Int64(key string, val int64) schemas.LogEventBuilder {
	b.attrs = append(b.attrs, slog.Int64(key, val))
	return b
}

func (b *slogEventBuilder) Send() {
	b.logger.LogAttrs(context.Background(), b.level, b.msg, b.attrs...)
}
