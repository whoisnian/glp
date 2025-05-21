package global

import (
	"context"
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

func SetupLogger(_ context.Context) {
	colorful = ansi.IsSupported(os.Stderr.Fd())

	options := logger.Options{Level: logger.LevelInfo, Colorful: colorful, AddSource: CFG.Debug}
	if CFG.Debug {
		options.Level = slog.LevelDebug
	}
	LOG = logger.New(logger.NewNanoHandler(os.Stderr, options))

	attrTagMap = map[string]slog.Attr{
		"CERT": slog.String("tag", "CERT"),
		"HTTP": slog.String("tag", "HTTP"),
		"TCP":  slog.String("tag", "TCP "),
	}

	generateMethodAttr := func(val string) slog.Attr {
		if colorful {
			return slog.Any("method", logger.AnsiString{Prefix: ansi.BlueFG, Value: val})
		} else {
			return slog.String("method", val)
		}
	}
	attrMethodMap = map[string]slog.Attr{
		"STORE":            generateMethodAttr("STORE  "),
		"LOAD":             generateMethodAttr("LOAD   "),
		http.MethodGet:     generateMethodAttr("GET    "),
		http.MethodPost:    generateMethodAttr("POST   "),
		http.MethodPut:     generateMethodAttr("PUT    "),
		http.MethodDelete:  generateMethodAttr("DELETE "),
		http.MethodHead:    generateMethodAttr("HEAD   "),
		http.MethodPatch:   generateMethodAttr("PATCH  "),
		http.MethodOptions: generateMethodAttr("OPTIONS"),
		http.MethodConnect: generateMethodAttr("CONNECT"),
		http.MethodTrace:   generateMethodAttr("TRACE  "),
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
	full := u.String()
	if colorful {
		l, r := 0, len(full)
		for i, ch := range full {
			if ch == rune('/') {
				l = i + 1
			} else if ch == rune('?') || ch == rune('#') {
				r = i
				break
			}
		}
		return slog.String("url", full[:l]+ansi.MagentaFG+full[l:r]+ansi.Reset+full[r:])
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
