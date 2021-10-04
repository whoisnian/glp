package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/whoisnian/glb/logger"
	"github.com/whoisnian/glp/cert"
	"github.com/whoisnian/glp/proxy"
)

const appName = "glp"

var isDebug = flag.Bool("d", false, "Output debug message")
var isColorful = flag.Bool("color", true, "Colorize the output")
var configDir = flag.String("c", "", "Custom config directory")
var host = flag.String("h", "127.0.0.1", "IP address to listen on")
var port = flag.String("p", "8889", "Port number to bind to")

func main() {
	flag.Parse()
	logger.SetDebug(*isDebug)
	logger.SetColorful(*isColorful)

	if *configDir == "" {
		var err error
		if *configDir, err = os.UserConfigDir(); err != nil {
			logger.Panic(err)
		}
	}
	if logger.IsDebug() {
		logger.Debug("Use config dir: ", filepath.Join(*configDir, appName))
	}

	cer, key, err := cert.LoadCA(filepath.Join(*configDir, appName))
	if err != nil {
		logger.Error(err)
		fmt.Printf("Do you want to generate the CA cert (yes/no)? ")
		var input string
		if fmt.Scanf("%s", &input); input != "yes" && input != "y" {
			logger.Error("Interrupted")
			return
		}
		logger.Info("Generating...")
		cer, key, err = cert.GenerateCA()
		if err != nil {
			logger.Panic(err)
		}
		cert.SaveCA(filepath.Join(*configDir, appName), cer, key)
	}
	if logger.IsDebug() {
		logger.Debug("Use CA cert:\n", cert.CerToString(cer))
		logger.Debug("Open in Firefox:\n", cert.CerToFirefoxLink(cer))
	}

	p := proxy.New(cer, key)
	go p.ListenAndServe(*host, *port)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	<-interrupt
}
