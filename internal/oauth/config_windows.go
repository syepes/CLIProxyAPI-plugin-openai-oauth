//go:build windows

package oauth

import "io/fs"

// permissionsTooOpen always reports false on Windows: Go synthesizes POSIX
// mode bits here from the read-only attribute alone (any writable file
// reports 0666), so the Unix group/other check in config_unix.go would
// reject every credential file regardless of its real NTFS ACL. Access
// control on Windows is the ACL, not these synthesized bits; this function
// relies on the regular-file and not-symlink checks the caller already does.
func permissionsTooOpen(fs.FileMode) bool {
	return false
}
