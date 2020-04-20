package internal

import (
	"log"
	"os"
)

var loggerPrefix = "[schism-lambda] : "

func SchismLog(dest *os.File) *log.Logger {
	return log.New(dest, loggerPrefix, log.Lshortfile|log.Lmsgprefix)
}
