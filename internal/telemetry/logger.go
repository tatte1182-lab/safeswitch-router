package telemetry

import (
	"log"
	"os"
)

func NewLogger(level string) *log.Logger {
	_ = level
	return log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
}
