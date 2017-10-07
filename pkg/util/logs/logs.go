package logs

import (
	"flag"
	"log"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/wait"
)

var logFlushFreq = pflag.Duration("log-flush-frequency", 6*time.Second, "Max number of seconds between log flushes")

// Path to log, stderr for now
func init() {
	flag.Set("logtostderr", "true")
}

// GlogWriter serves as a bridge between the standard log package and the glog package.
type GlogWriter struct{}

// Write implements the io.Writer interface.
func (writer GlogWriter) Write(data []byte) (n int, err error) {
	glog.Info(string(data))
	return len(data), nil
}

// InitLogs initializes logs the way we want for kubernetes.
func InitLogs() {
	log.SetOutput(GlogWriter{})
	log.SetFlags(0)
	// The default glog flush interval is 30 seconds, which is frighteningly long.
	go wait.Until(glog.Flush, *logFlushFreq, wait.NeverStop)
}

// FlushLogs flushes logs immediately.
func FlushLogs() {
	glog.Flush()
}

// NewLogger creates a new log.Logger which sends logs to glog.Info.
func NewLogger(prefix string) *log.Logger {
	return log.New(GlogWriter{}, prefix, 0)
}
