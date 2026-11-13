//go:build !unix

package privdrop

// Switch is not available on this platform: server.user and server.group
// are reported and ignored.
func Switch(userName, groupName string, files []string) (info, warning string, err error) {
	if userName == "" && groupName == "" {
		return "", "", nil
	}
	return "", "server.user / server.group are not supported on this platform and are ignored", nil
}
