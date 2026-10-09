package main

import (
	"embed"
	"fmt"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	windowsOptions "github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	if err := checkRuntime(); err != nil {
		showStartupError(err)
		return
	}
	a := NewApp()
	if e := wails.Run(&options.App{Title: "App Cleanup Doctor — Scan only", Width: 1380, Height: 900, MinWidth: 900, MinHeight: 640, BackgroundColour: options.NewRGBA(12, 18, 27, 255), AssetServer: &assetserver.Options{Assets: assets}, OnStartup: a.startup, Bind: []interface{}{a}, Windows: &windowsOptions.Options{DisableWindowIcon: false}}); e != nil {
		fmt.Println("Application could not start:", e)
	}
}
