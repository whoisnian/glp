package main

import (
	"fmt"

	"github.com/whoisnian/glb/util/osutil"
	"github.com/whoisnian/glp/cert"
	"github.com/whoisnian/glp/global"
	"github.com/whoisnian/glp/proxy"
)

func main() {
	global.Setup()
	if global.CFG.Version {
		fmt.Printf("%s %s(%s)\n", global.AppName, global.Version, global.BuildTime)
		return
	}

	cer, key, err := cert.Setup(global.CFG.CACertPath)
	if err != nil {
		global.LOG.Fatal(err.Error())
	}

	server := proxy.NewServer(cer, key)
	go func() {
		global.LOG.Infof("proxy server started: http://%s", global.CFG.ListenAddr)
		if err := server.ListenAndServe(global.CFG.ListenAddr); err != nil {
			global.LOG.Fatal(err.Error())
		}
	}()

	osutil.WaitForStop()
}
