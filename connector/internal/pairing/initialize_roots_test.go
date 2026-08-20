package pairing

import "testing"

// Roots reach initialize already projected into the POSIX form the control
// plane requires, so they are validated as POSIX paths on every platform.
func TestInitializeValidatesWorkspaceRootsAsPOSIXPaths(t *testing.T) {
	for _, test := range []struct {
		name     string
		roots    []string
		accepted bool
	}{
		{name: "projected drive root", roots: []string{"/c/Users/peter/code"}, accepted: true},
		{name: "projected UNC root", roots: []string{"/unc/nas/share/proj"}, accepted: true},
		{name: "posix root", roots: []string{"/work/project"}, accepted: true},
		{name: "filesystem root", roots: []string{"/"}},
		{name: "double slash", roots: []string{"//work/project"}},
		{name: "uncleaned", roots: []string{"/work/../project"}},
		{name: "trailing separator", roots: []string{"/work/project/"}},
		{name: "relative", roots: []string{"work/project"}},
		{name: "local windows path", roots: []string{`C:\work\project`}},
		{name: "control character", roots: []string{"/work/pro\x01ject"}},
		{name: "empty", roots: []string{""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, signer, _ := validStartRequest(t)
			request.WorkspaceRoots = test.roots
			client := signedClient(signer, nil)
			err := client.initialize(request)
			if test.accepted && err != nil {
				t.Fatalf("roots %q were rejected: %v", test.roots, err)
			}
			if !test.accepted && err == nil {
				t.Fatalf("roots %q were accepted", test.roots)
			}
		})
	}
}
