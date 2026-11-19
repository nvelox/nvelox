# Third-party code carried in this repository

## gofast

`third_party/gofast` is `github.com/yookoala/gofast` v0.8.0, the FastCGI
client behind `fastcgi` routes. `go.mod` points the module here
(`replace`), so nvelox is built with this copy and not with the published
module. Its licence is `third_party/gofast/LICENCE`.

The package's files are as published in v0.8.0, except where a comment
starting `nvelox:` marks a change. Its tests and its `go.sum` are not
carried.
