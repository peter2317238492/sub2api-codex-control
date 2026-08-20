package wspath

import (
	"path/filepath"
	"strings"
	"testing"
)

// portableRemotes are valid in the remote form on every supported platform:
// each names a Windows volume and is also a plain absolute POSIX path.
var portableRemotes = []string{
	"/c/Users/peter/code/app",
	"/c/a",
	"/d/work/project/sub/dir/leaf",
	"/unc/nas/share/proj",
	"/unc/nas/share/proj/deep/deeper/deepest",
	"/c/Пример/проект",
	"/c/日本語/アプリ/ソース",
	"/c/dir with spaces/app",
	"/c/.hidden/app",
	"/c/a.b.c/d-e_f/g~1",
	"/c/COM0/LPT0/CONS/NULL/COM10",
	"/c/..hidden/...deeper",
	"/c/ leading space/app",
}

func mustLocal(t *testing.T, mapper *Mapper, remote string) string {
	t.Helper()
	local, err := mapper.Local(remote)
	if err != nil {
		t.Fatalf("Local(%q) = %v", remote, err)
	}
	return local
}

func remoteOfSize(t *testing.T, size int) string {
	t.Helper()
	var builder strings.Builder
	builder.WriteString("/c")
	for {
		remaining := size - builder.Len()
		if remaining > 16 {
			builder.WriteString("/" + strings.Repeat("b", 15))
			continue
		}
		if remaining == 1 {
			builder.WriteString("a")
		} else if remaining > 1 {
			builder.WriteString("/" + strings.Repeat("a", remaining-1))
		}
		break
	}
	remote := builder.String()
	if len(remote) != size {
		t.Fatalf("remoteOfSize(%d) built %d bytes", size, len(remote))
	}
	return remote
}

// TestValidatePOSIXMatchesTheControlAPIContract pins the rule set the Control
// API applies to every workspace root and cwd, which is also the whole of the
// mapping on Linux and macOS.
func TestValidatePOSIXMatchesTheControlAPIContract(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		want      bool
	}{
		{name: "single component", candidate: "/a", want: true},
		{name: "nested", candidate: "/Users/peter/code/app", want: true},
		{name: "unicode", candidate: "/срм/проект", want: true},
		{name: "at the byte limit", candidate: remoteOfSize(t, MaxPathBytes), want: true},
		{name: "empty", candidate: ""},
		{name: "filesystem root", candidate: "/"},
		{name: "double slash", candidate: "//"},
		{name: "double slash prefix", candidate: "//host/share"},
		{name: "relative", candidate: "a/b"},
		{name: "dot relative", candidate: "./a"},
		{name: "trailing slash", candidate: "/a/"},
		{name: "dot component", candidate: "/a/./b"},
		{name: "parent component", candidate: "/a/../b"},
		{name: "empty component", candidate: "/a//b"},
		{name: "nul", candidate: "/a\x00b"},
		{name: "control character", candidate: "/a\x1fb"},
		{name: "over the byte limit", candidate: remoteOfSize(t, MaxPathBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePOSIX(test.candidate)
			if (err == nil) != test.want {
				t.Fatalf("validatePOSIX(%q) = %v, want valid = %t", test.candidate, err, test.want)
			}
		})
	}
}

func TestMapperProjectsRemotePathsBackAndForth(t *testing.T) {
	mapper := NewMapper()
	for _, remote := range portableRemotes {
		t.Run(remote, func(t *testing.T) {
			local := mustLocal(t, mapper, remote)
			projected, err := mapper.Remote(local)
			if err != nil {
				t.Fatalf("Remote(%q) = %v", local, err)
			}
			if projected != remote {
				t.Fatalf("Remote(Local(%q)) = %q", remote, projected)
			}
			if err := validatePOSIX(projected); err != nil {
				t.Fatalf("projection %q is not an absolute POSIX path: %v", projected, err)
			}
		})
	}
}

// TestMapperLocalOnlyAcceptsRoundTrippingRemotePaths is the property the
// mapping relies on to be usable as a security boundary: an accepted remote
// path is the one and only projection of the local path it names.
func TestMapperLocalOnlyAcceptsRoundTrippingRemotePaths(t *testing.T) {
	mapper := NewMapper()
	candidates := append([]string(nil), portableRemotes...)
	candidates = append(candidates,
		"",
		"/",
		"//",
		"//c/Users",
		"///c",
		"/c",
		"/d",
		"/unc",
		"/unc/nas",
		"/unc/nas/share",
		"/C/Users/peter",
		"/UNC/nas/share/proj",
		"/Unc/nas/share/proj",
		"/c/./app",
		"/c/../app",
		"/c//app",
		"/c/app/",
		"/c/app/.",
		"/c/app/..",
		"/c/app/../../etc",
		"/c/a\\b",
		"\\c\\a",
		"/c/a:b",
		"/c/a:b:c",
		"/c/a*b",
		"/c/a?b",
		"/c/a\"b",
		"/c/a<b",
		"/c/a>b",
		"/c/a|b",
		"/c/CON/app",
		"/c/app/nul.txt",
		"/c/app/LPT9",
		"/c/app/com1.log",
		"/c/trailing./app",
		"/c/trailing /app",
		"/c/app/trailing.",
		"/c/app/trailing ",
		"/tmp/project",
		"/cc/project",
		"/1/project",
		"/c/a\x01b",
		"/c/a\x7fb",
		"/c/app\u212a",
		"relative/path",
		"c:/Users/peter",
		remoteOfSize(t, MaxPathBytes),
		remoteOfSize(t, MaxPathBytes+1),
	)
	for _, remote := range candidates {
		local, err := mapper.Local(remote)
		if err != nil {
			continue
		}
		projected, err := mapper.Remote(local)
		if err != nil {
			t.Fatalf("Local(%q) = %q which does not project back: %v", remote, local, err)
		}
		if projected != remote {
			t.Fatalf("Remote(Local(%q)) = %q", remote, projected)
		}
	}
}

func TestMapperLocalRejectsPathsThatAreNotAbsolutePOSIX(t *testing.T) {
	mapper := NewMapper()
	tests := []struct {
		name   string
		remote string
	}{
		{name: "empty", remote: ""},
		{name: "relative", remote: "relative/path"},
		{name: "dot relative", remote: "./c/app"},
		{name: "filesystem root", remote: "/"},
		{name: "double slash", remote: "//"},
		{name: "double slash prefix", remote: "//c/app"},
		{name: "dot component", remote: "/c/./app"},
		{name: "parent component", remote: "/c/../app"},
		{name: "empty component", remote: "/c//app"},
		{name: "trailing slash", remote: "/c/app/"},
		{name: "trailing dot", remote: "/c/app/."},
		{name: "trailing parent", remote: "/c/app/.."},
		{name: "control character", remote: "/c/a\x01b"},
		{name: "newline", remote: "/c/a\nb"},
		{name: "over the byte limit", remote: remoteOfSize(t, MaxPathBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if local, err := mapper.Local(test.remote); err == nil {
				t.Fatalf("Local(%q) = %q, want error", test.remote, local)
			}
		})
	}
}

func TestMapperRemoteRejectsPathsThatAreNotAbsolute(t *testing.T) {
	mapper := NewMapper()
	tests := []struct {
		name  string
		local string
	}{
		{name: "empty", local: ""},
		{name: "relative", local: "relative/path"},
		{name: "dot relative", local: "./app"},
		{name: "parent relative", local: "../app"},
		{name: "bare name", local: "app"},
		{name: "over the byte limit", local: strings.Repeat("a", MaxPathBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if remote, err := mapper.Remote(test.local); err == nil {
				t.Fatalf("Remote(%q) = %q, want error", test.local, remote)
			}
		})
	}
}

func TestMapperAcceptsAPathAtTheByteLimit(t *testing.T) {
	mapper := NewMapper()
	remote := remoteOfSize(t, MaxPathBytes)
	local := mustLocal(t, mapper, remote)
	projected, err := mapper.Remote(local)
	if err != nil {
		t.Fatalf("Remote(%q) = %v", local, err)
	}
	if projected != remote {
		t.Fatalf("Remote(Local(%q)) = %q", remote, projected)
	}
	over := remoteOfSize(t, MaxPathBytes+1)
	if _, err := mapper.Local(over); err == nil {
		t.Fatalf("Local accepted %d bytes", len(over))
	}
}

func TestMapperProjectsDeeplyNestedAndUnicodePaths(t *testing.T) {
	mapper := NewMapper()
	components := make([]string, 0, 64)
	for index := 0; index < 64; index++ {
		components = append(components, "уровень")
	}
	remote := "/c/" + strings.Join(components, "/")
	local := mustLocal(t, mapper, remote)
	projected, err := mapper.Remote(local)
	if err != nil {
		t.Fatalf("Remote(%q) = %v", local, err)
	}
	if projected != remote {
		t.Fatalf("Remote(Local(%q)) = %q", remote, projected)
	}
}

func TestValidateRemoteAgreesWithLocal(t *testing.T) {
	mapper := NewMapper()
	for _, remote := range portableRemotes {
		if err := mapper.ValidateRemote(remote); err != nil {
			t.Fatalf("ValidateRemote(%q) = %v", remote, err)
		}
	}
	for _, remote := range []string{"", "/", "//host/share", "relative/path", "/c/./app", "/c/app/", "/c/a\x01b"} {
		if err := mapper.ValidateRemote(remote); err == nil {
			t.Fatalf("ValidateRemote(%q) = nil, want error", remote)
		}
	}
}

func TestRemoteRootsProjectsAndDropsDuplicates(t *testing.T) {
	mapper := NewMapper()
	first := mustLocal(t, mapper, "/c/work/one")
	second := mustLocal(t, mapper, "/unc/nas/share/two")
	roots, err := mapper.RemoteRoots([]string{first, second, first})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/c/work/one", "/unc/nas/share/two"}
	if len(roots) != len(want) {
		t.Fatalf("RemoteRoots = %#v, want %#v", roots, want)
	}
	for index, root := range roots {
		if root != want[index] {
			t.Fatalf("RemoteRoots = %#v, want %#v", roots, want)
		}
	}
}

func TestRemoteRootsReportsTheOffendingIndex(t *testing.T) {
	mapper := NewMapper()
	valid := mustLocal(t, mapper, "/c/work/one")
	roots, err := mapper.RemoteRoots([]string{valid, "relative/path"})
	if err == nil {
		t.Fatalf("RemoteRoots = %#v, want error", roots)
	}
	if !strings.Contains(err.Error(), "workspace root 1") {
		t.Fatalf("RemoteRoots error = %v, want it to name index 1", err)
	}
}

func TestRemoteRootsAcceptsAnEmptySlice(t *testing.T) {
	mapper := NewMapper()
	roots, err := mapper.RemoteRoots(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 0 {
		t.Fatalf("RemoteRoots = %#v, want empty", roots)
	}
}

func TestSamePathAndContainsMatchLocalPaths(t *testing.T) {
	mapper := NewMapper()
	root := mustLocal(t, mapper, "/c/work")
	child := filepath.Join(root, "sub", "dir")
	sibling := mustLocal(t, mapper, "/c/work-other")
	prefixed := mustLocal(t, mapper, "/c/workspace")
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{name: "same path", got: mapper.SamePath(root, root), want: true},
		{name: "same path uncleaned", got: mapper.SamePath(root, root+string(filepath.Separator)), want: true},
		{name: "same path with dot component", got: mapper.SamePath(root, filepath.Join(root, ".")), want: true},
		{name: "different path", got: mapper.SamePath(root, child), want: false},
		{name: "same path empty left", got: mapper.SamePath("", root), want: false},
		{name: "same path empty right", got: mapper.SamePath(root, ""), want: false},
		{name: "contains itself", got: mapper.Contains(root, root), want: true},
		{name: "contains child", got: mapper.Contains(root, child), want: true},
		{name: "contains normalised child", got: mapper.Contains(root, filepath.Join(root, "sub", "..", "other")), want: true},
		{name: "escaping child", got: mapper.Contains(root, filepath.Join(root, "..", "elsewhere")), want: false},
		{name: "sibling sharing a prefix", got: mapper.Contains(root, sibling), want: false},
		{name: "longer name sharing a prefix", got: mapper.Contains(root, prefixed), want: false},
		{name: "parent is not contained", got: mapper.Contains(child, root), want: false},
		{name: "contains empty root", got: mapper.Contains("", child), want: false},
		{name: "contains empty child", got: mapper.Contains(root, ""), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("%s = %t, want %t", test.name, test.got, test.want)
			}
		})
	}
}

func TestZeroValueMapperIsUsable(t *testing.T) {
	var mapper Mapper
	local, err := mapper.Local("/c/work/app")
	if err != nil {
		t.Fatal(err)
	}
	remote, err := mapper.Remote(local)
	if err != nil {
		t.Fatal(err)
	}
	if remote != "/c/work/app" {
		t.Fatalf("Remote(Local(%q)) = %q", "/c/work/app", remote)
	}
	if !mapper.Contains(local, local) {
		t.Fatalf("Contains(%q, %q) = false", local, local)
	}
}
