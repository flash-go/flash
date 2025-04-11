package logger

import (
	"github.com/rs/zerolog"
)

type ConsoleInterface interface {
	Write(p []byte) (int, error)
}

type Console struct {
	writer zerolog.ConsoleWriter
}

func NewConsole(writer zerolog.ConsoleWriter) ConsoleInterface {
	return &Console{writer}
}

func (c *Console) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}
