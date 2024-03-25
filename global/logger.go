package global

import (
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/whoisnian/glb/ansi"
	"github.com/whoisnian/glb/logger"
)

var (
	LOG *logger.Logger

	colorful      bool
	attrTagMap    map[string]slog.Attr
	attrMethodMap map[string]slog.Attr
)

func SetupLogger() {
	colorful = ansi.IsSupported(os.Stderr.Fd())

	if CFG.Debug {
		LOG = logger.New(logger.NewNanoHandler(os.Stderr, logger.NewOptions(
			logger.LevelDebug, colorful, true,
		)))
	} else {
		LOG = logger.New(logger.NewNanoHandler(os.Stderr, logger.NewOptions(
			logger.LevelInfo, colorful, false,
		)))
	}

	attrTagMap = map[string]slog.Attr{
		"CERT": slog.String("tag", "CERT"),
		"HTTP": slog.String("tag", "HTTP"),
		"TCP":  slog.String("tag", "TCP "),
	}

	generate := func(val string) slog.Attr {
		if colorful {
			return slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: val})
		} else {
			return slog.String("method", val)
		}
	}
	attrMethodMap = map[string]slog.Attr{
		"STORE":            generate("STORE  "),
		"LOAD":             generate("LOAD   "),
		http.MethodGet:     generate("GET    "),
		http.MethodPost:    generate("POST   "),
		http.MethodPut:     generate("PUT    "),
		http.MethodDelete:  generate("DELETE "),
		http.MethodHead:    generate("HEAD   "),
		http.MethodPatch:   generate("PATCH  "),
		http.MethodOptions: generate("OPTIONS"),
		http.MethodConnect: generate("CONNECT"),
		http.MethodTrace:   generate("TRACE  "),
	}
}

func LogAttrTag(t string) slog.Attr {
	if attr, ok := attrTagMap[t]; ok {
		return attr
	}
	return slog.String("tag", "ERR:"+t)
}

func LogAttrMethod(m string) slog.Attr {
	if attr, ok := attrMethodMap[m]; ok {
		return attr
	}
	return slog.String("method", "ERR:"+m)
}

func LogAttrURL(u *url.URL) slog.Attr {
	if colorful {
		fullStr := u.String()
		l, r := 0, len(fullStr)
		for i, ch := range fullStr {
			if ch == rune('/') {
				l = i + 1
			} else if ch == rune('?') || ch == rune('#') {
				r = i
				break
			}
		}
		return slog.String("url", fullStr[:l]+ansi.MagentaFG+fullStr[l:r]+ansi.Reset+fullStr[r:])
	} else {
		return slog.String("url", u.String())
	}
}

func LogAttrDuration(d time.Duration) slog.Attr {
	if colorful {
		return slog.Any("duration", logger.AnsiString{
			Prefix: ansi.YellowFG,
			Value:  strconv.FormatInt(d.Milliseconds(), 10) + "ms"},
		)
	} else {
		return slog.String("duration", strconv.FormatInt(d.Milliseconds(), 10)+"ms")
	}
}
