package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/whoisnian/glb/logger"
	"github.com/whoisnian/glb/util/osutil"
	"github.com/whoisnian/glp/ca"
	"github.com/whoisnian/glp/global"
	"github.com/whoisnian/glp/proxy"
)

func main() {
	ctx := context.Background()
	global.SetupConfig(ctx)
	global.SetupLogger(ctx)
	global.LOG.Debugf(ctx, "use config: %+v", global.CFG)

	if global.CFG.Version {
		fmt.Printf("%s version %s built with %s at %s\n", global.AppName, global.Version, runtime.Version(), global.BuildTime)
		return
	}

	ca.Setup(ctx)
	server, err := proxy.NewServer(global.CFG.ListenAddr, global.CFG.RelayProxy, global.CFG.KeyLogFile)
	if err != nil {
		global.LOG.Fatal(ctx, "proxy.NewServer", logger.Error(err))
	}
	go func() {
		global.LOG.Infof(ctx, "proxy server started: http://%s", global.CFG.ListenAddr)
		if err := server.ListenAndServe(); errors.Is(err, proxy.ErrServerClosed) {
			global.LOG.Warn(ctx, "proxy server shutting down")
		} else if err != nil {
			global.LOG.Fatal(ctx, "server.ListenAndServe", logger.Error(err))
		}
	}()

	osutil.WaitForStop()

	shutdownCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		global.LOG.Warn(ctx, "server.Shutdown", logger.Error(err))
	}
}
