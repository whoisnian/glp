package global

import (
	"os"

	"github.com/whoisnian/glb/ansi"
	"github.com/whoisnian/glb/config"
	"github.com/whoisnian/glb/logger"
)

type Config struct {
	Debug      bool   `flag:"d,false,Enable debug output"`
	ListenAddr string `flag:"l,127.0.0.1:8080,HTTP proxy server listen addr"`
	CACertPath string `flag:"ca,~/.mitmproxy/mitmproxy-ca.pem,CA certificate to issue leaf certificates"`
	RelayProxy string `flag:"proxy,,Relay to upstream proxy (socks5/http/https)"`
	KeyLogFile string `flag:"keylog,,Key log file for TLS decryption in wireshark"`
	Version    bool   `flag:"v,false,Show version and quit"`
}

var (
	CFG Config
	LOG *logger.Logger

	AppName   = "glp"
	Version   = "unknown"
	BuildTime = "unknown"
)

func Setup() {
	err := config.FromCommandLine(&CFG)
	if err != nil {
		panic(err)
	}

	level := logger.LevelInfo
	if CFG.Debug {
		level = logger.LevelDebug
	}
	LOG = logger.New(logger.NewNanoHandler(os.Stderr, logger.NewOptions(
		level, ansi.IsSupported(os.Stderr.Fd()), false,
	)))
}
