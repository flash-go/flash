package logger

import (
	"io"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

const loggerDefaultLevel = zerolog.InfoLevel

type Logger interface {
	SetLevel(level zerolog.Level) Logger
	Log() *zerolog.Logger
	Printf(format string, args ...any)
}

type logger struct {
	zerolog zerolog.Logger
}

func New(writer io.Writer) Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.SetGlobalLevel(loggerDefaultLevel)
	return &logger{zerolog.New(writer).With().Timestamp().Logger()}
}

func (l *logger) SetLevel(level zerolog.Level) Logger {
	zerolog.SetGlobalLevel(level)
	return l
}

func (l *logger) Log() *zerolog.Logger {
	return &l.zerolog
}

func (l *logger) Printf(format string, args ...any) {
	l.zerolog.Printf(format, args...)
}
