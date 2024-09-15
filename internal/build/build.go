package build

// Version is dynamically set by the toolchain or overridden by the Makefile.
var version = "DEV"

// Date is dynamically set at build time in the Makefile.
var date = "" // YYYY-MM-DD

func Version() string {
	return version
}

func Date() string {
	return date
}
