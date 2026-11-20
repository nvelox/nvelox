# Third-party code carried in this repository

## gofast

`third_party/gofast` is `github.com/yookoala/gofast` v0.8.0, the FastCGI
client behind `fastcgi` routes. `go.mod` points the module here
(`replace`), so nvelox is built with this copy and not with the published
module. Its licence is `third_party/gofast/LICENCE`.

The package's files are as published in v0.8.0, except where a comment
starting `nvelox:` marks a change. Its tests and its `go.sum` are not
carried.

Changes from v0.8.0:

- `client.go`, `writeResponse`: when the response head is refused, or
  writing to the client fails, the rest of the upstream's output is read
  and dropped, so the request ends. In v0.8.0 the request stayed open until
  the client went away.
- `client.go`, `writeResponse`: a `Status` line it cannot read, or a header
  line without a colon, is answered 500, as v0.8.0 answers the other
  response heads it refuses. v0.8.0 wrote no status for these two, which
  net/http sends as an empty 200.
- `client.go`, `writeResponse`: a response head of up to 64 KiB is read,
  however long its lines (a line longer than the reader's 1 KiB buffer is
  read in parts); a larger head is answered 500. v0.8.0 refused any line
  over 1 KiB and set no limit on the head as a whole.
