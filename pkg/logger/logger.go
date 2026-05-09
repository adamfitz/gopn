package logger

import (
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/natefinch/lumberjack"
)

func init() {
	home, _ := os.UserHomeDir()

	logPath := filepath.Join(home, ".config", "gopn", "gopn.log")

	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		log.SetOutput(io.Discard)
		return
	}

	logWriter := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    5,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	}

	log.SetOutput(logWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
