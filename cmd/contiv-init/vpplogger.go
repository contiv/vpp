package main

import (
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"os"
)

type vppLogger struct {
	logger logging.Logger
}

func newVPPLogger() *vppLogger {
	l := &vppLogger{
		logger: logrus.NewLogger("vpp"),
	}
	l.logger.SetOutput(os.Stdout)
	l.logger.SetLevel(logging.DebugLevel)
	return l
}

func (l vppLogger) Write(p []byte) (n int, err error) {
	l.logger.Debugf("%s", p)
	return len(p), nil
}
