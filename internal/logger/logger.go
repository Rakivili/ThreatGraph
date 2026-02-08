package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Level is the logging level.
type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

// Logger is a basic logger wrapper.
type Logger struct {
	level   Level
	logger  *log.Logger
	enabled bool
}

var globalLogger *Logger

// Init initializes the logger.
func Init(enabled bool, levelStr, logFile string, console bool) error {
	if !enabled {
		globalLogger = &Logger{enabled: false}
		return nil
	}

	level := parseLevel(levelStr)
	var writers []io.Writer

	if logFile != "" {
		dir := filepath.Dir(logFile)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create log directory: %w", err)
			}
		}
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		writers = append(writers, f)
	}

	if console || len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	globalLogger = &Logger{
		level:   level,
		logger:  log.New(io.MultiWriter(writers...), "", 0),
		enabled: true,
	}

	return nil
}

func parseLevel(levelStr string) Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return Debug
	case "info":
		return Info
	case "warn", "warning":
		return Warn
	case "error":
		return Error
	default:
		return Info
	}
}

func formatMessage(level Level, format string, args ...interface{}) string {
	levelStr := "INFO"
	switch level {
	case Debug:
		levelStr = "DEBUG"
	case Info:
		levelStr = "INFO"
	case Warn:
		levelStr = "WARN"
	case Error:
		levelStr = "ERROR"
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	return fmt.Sprintf("[%s] [%s] %s", ts, levelStr, msg)
}

// Debugf logs a debug message.
func Debugf(format string, args ...interface{}) {
	if globalLogger == nil || !globalLogger.enabled || globalLogger.level > Debug {
		return
	}
	globalLogger.logger.Println(formatMessage(Debug, format, args...))
}

// Infof logs an info message.
func Infof(format string, args ...interface{}) {
	if globalLogger == nil || !globalLogger.enabled || globalLogger.level > Info {
		return
	}
	globalLogger.logger.Println(formatMessage(Info, format, args...))
}

// Warnf logs a warning.
func Warnf(format string, args ...interface{}) {
	if globalLogger == nil || !globalLogger.enabled || globalLogger.level > Warn {
		return
	}
	globalLogger.logger.Println(formatMessage(Warn, format, args...))
}

// Errorf logs an error message.
func Errorf(format string, args ...interface{}) {
	if globalLogger == nil || !globalLogger.enabled || globalLogger.level > Error {
		return
	}
	globalLogger.logger.Println(formatMessage(Error, format, args...))
}
