package global

import "github.com/whoisnian/glb/config"

var CFG Config

type Config struct {
	Debug   bool `flag:"d,false,Enable debug output"`
	Version bool `flag:"v,false,Show version and quit"`

	ListenAddr string `flag:"l,127.0.0.1:8080,HTTP proxy server listen addr"`
	CACertPath string `flag:"ca,~/.mitmproxy/mitmproxy-ca.pem,CA certificate to issue leaf certificates"`
	RelayProxy string `flag:"proxy,,Relay to upstream proxy (socks5/http/https)"`
	KeyLogFile string `flag:"keylog,,Key log file for TLS decryption in wireshark"`
}

func SetupConfig() {
	err := config.FromCommandLine(&CFG)
	if err != nil {
		panic(err)
	}
}
