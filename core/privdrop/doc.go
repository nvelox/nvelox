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
//
// Started as root, nvelox reads the config and every file it names (TLS
// certificates and keys, CA files, PROXY key files, error pages) as root, so
// none of them, nor their directories, may be writable by that user: whoever
// can change them can change what root reads. The log directory may be;
// log files are opened without following a symbolic link and handed over by
// descriptor.
package privdrop
