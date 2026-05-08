package logger

import (
	"log"
	"os"
	"path/filepath"

	"github.com/natefinch/lumberjack"
)

var Log *log.Logger

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		// fallback to stdout if home cannot be resolved
		Log = log.New(os.Stdout, "", log.LstdFlags)
		return
	}

	logPath := filepath.Join(home, ".config", "gopn", "gopn.log")

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		Log = log.New(os.Stdout, "", log.LstdFlags)
		return
	}

	// Lumberjack handles rotation automatically
	rotator := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    5,  // megabytes
		MaxBackups: 5,  // keep 5 old logs
		MaxAge:     30, // days
		Compress:   true,
	}

	Log = log.New(rotator, "", log.LstdFlags)
}
