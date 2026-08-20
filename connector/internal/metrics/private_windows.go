package metrics

import "os"

// restrictTemporaryFile is a no-op: securefile creates the file with a
// protected access control list already attached, and Windows mode bits only
// encode the read-only attribute.
func restrictTemporaryFile(*os.File) error {
	return nil
}

// privateRegularMode deliberately ignores the permission bits. Privacy on
// Windows lives in the owner and the discretionary access control list, both of
// which securefile has already validated for every mode this package inspects.
func privateRegularMode(mode os.FileMode) bool {
	return mode.IsRegular()
}
