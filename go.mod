module main.go

go 1.19

// Fix a bug in issue config
replace gopkg.in/alecthomas/kingpin.v2 => github.com/alecthomas/kingpin/v2 v2.4.0

// Use the latest u-root package with seccomp support
replace github.com/u-root/u-root => github.com/u-root/u-root v0.14.1-0.20241107071304-f908619d0238
