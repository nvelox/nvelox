// Package privdrop switches the process to the user and group named by
// server.user and server.group once nvelox holds its listening sockets and
// log files, as nginx and HAProxy do: started as root, nvelox binds its ports
// and then runs without root rights.
//
// After the switch a reload can still re-read the config, the certificates
// and the log files, so they must be readable (log files writable) by that
// user; Switch hands the open log files to it. A reload cannot bind a new
// listener on a port below 1024 (restart nvelox for that), and a reload does
// not change the user or group.
package privdrop
