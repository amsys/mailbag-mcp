// web.go embeds the setup page: HTML, CSS, JavaScript and the provider
// presets. The files have no build step and make no request to another
// host.
//
// arch: DS13.4, DS13.8

package main

import (
	"embed"
	"io/fs"
)

//go:embed web
var webEmbed embed.FS

// webFiles holds the embedded web files at the root: index.html,
// app.js, style.css and presets.json.
func webFiles() fs.FS {
	sub, err := fs.Sub(webEmbed, "web")
	if err != nil {
		panic(err) // the "web" directory is embedded at build time
	}
	return sub
}
