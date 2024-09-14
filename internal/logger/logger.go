package logger

import (
	"log"
	"os"
)

type Level int8

const (
	InfoLevel Level = iota
	WarnLevel
	ErrorLevel
	Disabled

	DebugLevel Level = -1
	TraceLevel Level = -2
)

type LogWriter interface {
	Printf(format string, v ...any)
	Errorf(format string, v ...any)
	Warnf(format string, v ...any)
	Infof(format string, v ...any)
	Debugf(format string, v ...any)
	Tracef(format string, v ...any)
	Level() Level
	SetLevel(Level)
	ShouldLevel(Level) bool
}

type Logger struct {
	out   *log.Logger
	level Level
}

var _ LogWriter = (*Logger)(nil)

func New() *Logger {
	return &Logger{
		out: log.New(os.Stderr, "", 0),
	}
}

func (l *Logger) Printf(format string, v ...any) {
	l.out.Printf(format, v...)
}

func (l *Logger) Errorf(format string, v ...any) {
	if l.ShouldLevel(ErrorLevel) {
		l.out.Printf("[ERROR] "+format, v...)
	}
}

func (l *Logger) Warnf(format string, v ...any) {
	if l.ShouldLevel(WarnLevel) {
		l.out.Printf("[WARNING] "+format, v...)
	}
}

func (l *Logger) Infof(format string, v ...any) {
	if l.ShouldLevel(InfoLevel) {
		l.out.Printf("[INFO] "+format, v...)
	}
}

func (l *Logger) Debugf(format string, v ...any) {
	if l.ShouldLevel(DebugLevel) {
		l.out.Printf("[DEBUG] "+format, v...)
	}
}

func (l *Logger) Tracef(format string, v ...any) {
	if l.ShouldLevel(TraceLevel) {
		l.out.Printf("[TRACE] "+format, v...)
	}
}

func (l *Logger) Level() Level {
	return l.level
}

func (l *Logger) SetLevel(lvl Level) {
	l.level = lvl
}

func (l *Logger) ShouldLevel(lvl Level) bool {
	if l.level == Disabled {
		return false
	}
	return lvl >= l.level
}
