//go:build !windows

package oauth

import "io/fs"

// permissionsTooOpen reports whether group or other has any access.
// Windows has no POSIX permission bits; see config_windows.go.
func permissionsTooOpen(mode fs.FileMode) bool {
	return mode.Perm()&0077 != 0
}
