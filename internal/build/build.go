package build

import "runtime/debug"

// Version is dynamically set by the toolchain or overridden by the Makefile.
var version = "DEV"

// Date is dynamically set at build time in the Makefile.
var date = "" // YYYY-MM-DD

func init() {
	if version == "DEV" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}
}

func Version() string {
	return version
}

func Date() string {
	return date
}
