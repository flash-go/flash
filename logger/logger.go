package logger

import (
	"errors"
	"io"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

const loggerDefaultLevel = zerolog.InfoLevel

type Logger interface {
	SetLevel(level int) error
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

func (l *logger) SetLevel(level int) error {
	if level < -1 || level > 7 {
		return errors.New("invalid log level")
	}
	zerolog.SetGlobalLevel(zerolog.Level(level))
	return nil
}

func (l *logger) Log() *zerolog.Logger {
	return &l.zerolog
}

func (l *logger) Printf(format string, args ...any) {
	l.zerolog.Printf(format, args...)
}
