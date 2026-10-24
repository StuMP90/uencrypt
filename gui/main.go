// Command uencrypt-gui is the desktop app for uencrypt: the same keyring,
// file formats and checks as the CLI, behind a Wails (WebView) front end.
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var icon []byte

func main() {
	app := NewApp()
	err := wails.Run(&options.App{
		Title:     "uEncrypt",
		Width:     1040,
		Height:    720,
		MinWidth:  760,
		MinHeight: 520,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 26, G: 29, B: 33, A: 255},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		DragAndDrop: &options.DragAndDrop{
			EnableFileDrop:     true,
			DisableWebViewDrop: true,
		},
		// A second launch (for example double-clicking a .age file while
		// the app is open) hands its files to the running window.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "io.github.stump90.uencrypt",
			OnSecondInstanceLaunch: app.secondInstance,
		},
		Bind: []any{app},
		Windows: &windows.Options{
			Theme: windows.Dark,
		},
		Linux: &linux.Options{
			Icon:        icon,
			ProgramName: "uencrypt-gui",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
