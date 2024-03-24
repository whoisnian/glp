package global

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/whoisnian/glb/ansi"
	"github.com/whoisnian/glb/logger"
)

var LOG *logger.Logger

func SetupLogger() {
	if CFG.Debug {
		LOG = logger.New(logger.NewNanoHandler(os.Stderr, logger.NewOptions(
			logger.LevelDebug, ansi.IsSupported(os.Stderr.Fd()), true,
		)))
	} else {
		LOG = logger.New(logger.NewNanoHandler(os.Stderr, logger.NewOptions(
			logger.LevelInfo, ansi.IsSupported(os.Stderr.Fd()), false,
		)))
	}
}

var LogAttrMap = map[string]slog.Attr{
	"CERT": slog.String("tag", "CERT"),
	"HTTP": slog.String("tag", "HTTP"),
	"TCP":  slog.String("tag", "TCP "),

	"STORE": slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "STORE  "}),
	"LOAD":  slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "LOAD   "}),

	http.MethodGet:     slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "GET    "}),
	http.MethodPost:    slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "POST   "}),
	http.MethodPut:     slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "PUT    "}),
	http.MethodDelete:  slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "DELETE "}),
	http.MethodHead:    slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "HEAD   "}),
	http.MethodPatch:   slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "PATCH  "}),
	http.MethodOptions: slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "OPTIONS"}),
	http.MethodConnect: slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "CONNECT"}),
	http.MethodTrace:   slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: "TRACE  "}),
}
