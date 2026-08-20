//go:build windows

package wspath

import (
	"strings"
	"testing"
)

func TestRemoteProjectsWindowsPaths(t *testing.T) {
	mapper := NewMapper()
	tests := []struct {
		name  string
		local string
		want  string
	}{
		{name: "drive path", local: `C:\Users\peter\code\app`, want: "/c/Users/peter/code/app"},
		{name: "lower-case drive", local: `c:\a\b`, want: "/c/a/b"},
		{name: "forward slashes", local: `D:/work/app`, want: "/d/work/app"},
		{name: "mixed separators", local: `D:/work\app`, want: "/d/work/app"},
		{name: "trailing separator", local: `C:\Users\peter\`, want: "/c/Users/peter"},
		{name: "unc path", local: `\\nas\share\proj`, want: "/unc/nas/share/proj"},
		{name: "unc forward slashes", local: `//nas/share/proj`, want: "/unc/nas/share/proj"},
		{name: "unc trailing separator", local: `\\nas\share\proj\`, want: "/unc/nas/share/proj"},
		{name: "unc deep path", local: `\\nas\share\a\b\c\d`, want: "/unc/nas/share/a/b/c/d"},
		{name: "case is preserved below the drive", local: `C:\Users\Peter\Code`, want: "/c/Users/Peter/Code"},
		{name: "unicode components", local: `C:\Пример\проект`, want: "/c/Пример/проект"},
		{name: "spaces", local: `C:\Program Files\app`, want: "/c/Program Files/app"},
		{name: "near-miss device names", local: `C:\COM0\CONS\NULL\COM10`, want: "/c/COM0/CONS/NULL/COM10"},
		{name: "dotfile", local: `C:\app\.gitignore`, want: "/c/app/.gitignore"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := mapper.Remote(test.local)
			if err != nil {
				t.Fatalf("Remote(%q) = %v", test.local, err)
			}
			if got != test.want {
				t.Fatalf("Remote(%q) = %q, want %q", test.local, got, test.want)
			}
			back, err := mapper.Local(got)
			if err != nil {
				t.Fatalf("Local(%q) = %v", got, err)
			}
			if again, err := mapper.Remote(back); err != nil || again != got {
				t.Fatalf("Remote(Local(%q)) = %q, %v", got, again, err)
			}
		})
	}
}

func TestRemoteRejectsWindowsPathsThatCannotBeProjected(t *testing.T) {
	mapper := NewMapper()
	tests := []struct {
		name  string
		local string
	}{
		{name: "drive only", local: `C:`},
		{name: "drive relative", local: `C:app`},
		{name: "volume root", local: `C:\`},
		{name: "volume root forward slash", local: `C:/`},
		{name: "rooted relative", local: `\app`},
		{name: "relative", local: `app\sub`},
		{name: "unc host only", local: `\\nas`},
		{name: "unc share root", local: `\\nas\share`},
		{name: "unc share root trailing separator", local: `\\nas\share\`},
		{name: "parent component", local: `C:\a\..\b`},
		{name: "dot component", local: `C:\a\.\b`},
		{name: "empty component", local: `C:\a\\b`},
		{name: "device namespace", local: `\\?\C:\a\b`},
		{name: "device path", local: `\\.\PhysicalDrive0`},
		{name: "reserved device name", local: `C:\CON\app`},
		{name: "reserved device name with extension", local: `C:\app\nul.txt`},
		{name: "reserved port name", local: `C:\app\LPT9`},
		{name: "reserved port name lower case", local: `C:\app\com1.log`},
		{name: "reserved device name in a unc share", local: `\\nas\share\aux`},
		{name: "component ends in a dot", local: `C:\trailing.\app`},
		{name: "component ends in a space", local: `C:\trailing \app`},
		{name: "alternate data stream", local: `C:\app\file:stream`},
		{name: "second colon", local: `C:\app\a:b:c`},
		{name: "wildcard star", local: `C:\app\*`},
		{name: "wildcard question mark", local: `C:\app\?`},
		{name: "quote", local: `C:\app\"q"`},
		{name: "less than", local: `C:\app\<q`},
		{name: "greater than", local: `C:\app\>q`},
		{name: "pipe", local: `C:\app\a|b`},
		{name: "control character", local: "C:\\app\\a\x01b"},
		{name: "digit drive", local: `1:\app`},
		{name: "over the byte limit", local: `C:\` + strings.Repeat("a", MaxPathBytes)},
		{name: "projection over the byte limit", local: `\\nas\share\` + strings.Repeat("a", MaxPathBytes-12)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if remote, err := mapper.Remote(test.local); err == nil {
				t.Fatalf("Remote(%q) = %q, want error", test.local, remote)
			}
		})
	}
}

func TestLocalMapsRemotePathsToWindowsPaths(t *testing.T) {
	mapper := NewMapper()
	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{name: "drive path", remote: "/c/Users/peter/code/app", want: `C:\Users\peter\code\app`},
		{name: "single component", remote: "/d/work", want: `D:\work`},
		{name: "unc path", remote: "/unc/nas/share/proj", want: `\\nas\share\proj`},
		{name: "unc deep path", remote: "/unc/nas/share/a/b/c", want: `\\nas\share\a\b\c`},
		{name: "unicode components", remote: "/c/Пример/проект", want: `C:\Пример\проект`},
		{name: "dotfile", remote: "/c/app/.gitignore", want: `C:\app\.gitignore`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := mapper.Local(test.remote)
			if err != nil {
				t.Fatalf("Local(%q) = %v", test.remote, err)
			}
			if got != test.want {
				t.Fatalf("Local(%q) = %q, want %q", test.remote, got, test.want)
			}
		})
	}
}

func TestLocalRejectsRemotePathsThatDoNotNameAWindowsPath(t *testing.T) {
	mapper := NewMapper()
	tests := []struct {
		name   string
		remote string
	}{
		{name: "upper-case drive", remote: "/C/Users/peter"},
		{name: "upper-case unc prefix", remote: "/UNC/nas/share/proj"},
		{name: "mixed-case unc prefix", remote: "/Unc/nas/share/proj"},
		{name: "volume root", remote: "/c"},
		{name: "unc prefix alone", remote: "/unc"},
		{name: "unc host alone", remote: "/unc/nas"},
		{name: "unc share root", remote: "/unc/nas/share"},
		{name: "posix path", remote: "/tmp/project"},
		{name: "multi-letter volume", remote: "/cc/project"},
		{name: "digit volume", remote: "/1/project"},
		{name: "backslash", remote: `/c/a\b`},
		{name: "backslash separator", remote: `\c\a`},
		{name: "alternate data stream", remote: "/c/app/file:stream"},
		{name: "drive colon", remote: "/c:/app"},
		{name: "wildcard star", remote: "/c/app/*"},
		{name: "wildcard question mark", remote: "/c/app/?"},
		{name: "quote", remote: `/c/app/"q"`},
		{name: "less than", remote: "/c/app/<q"},
		{name: "greater than", remote: "/c/app/>q"},
		{name: "pipe", remote: "/c/app/a|b"},
		{name: "reserved device name", remote: "/c/CON/app"},
		{name: "reserved device name with extension", remote: "/c/app/nul.txt"},
		{name: "reserved port name", remote: "/c/app/lpt3"},
		{name: "reserved device name in a unc share", remote: "/unc/nas/share/aux"},
		{name: "component ends in a dot", remote: "/c/app/trailing."},
		{name: "component ends in a space", remote: "/c/app/trailing "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if local, err := mapper.Local(test.remote); err == nil {
				t.Fatalf("Local(%q) = %q, want error", test.remote, local)
			}
		})
	}
}

func TestPathMatchingIsCaseInsensitiveOnWindows(t *testing.T) {
	mapper := NewMapper()
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{name: "same path in a different case", got: mapper.SamePath(`C:\Users\Peter`, `c:\users\peter`), want: true},
		{name: "same unc path in a different case", got: mapper.SamePath(`\\NAS\Share\Proj`, `\\nas\share\proj`), want: true},
		{name: "same path with mixed separators", got: mapper.SamePath(`C:\Users\Peter`, `C:/Users/Peter/`), want: true},
		{name: "different path", got: mapper.SamePath(`C:\Users\Peter`, `C:\Users\Peters`), want: false},
		{name: "child in a different case", got: mapper.Contains(`C:\Work`, `c:\work\sub\dir`), want: true},
		{name: "root in a different case", got: mapper.Contains(`c:\work`, `C:\WORK`), want: true},
		{name: "sibling sharing a prefix", got: mapper.Contains(`C:\Work`, `c:\work-other`), want: false},
		{name: "longer name sharing a prefix", got: mapper.Contains(`C:\Work`, `c:\workspace`), want: false},
		{name: "escaping child", got: mapper.Contains(`C:\Work`, `C:\Work\..\Other`), want: false},
		{name: "different volume", got: mapper.Contains(`C:\Work`, `D:\Work\sub`), want: false},
		// U+212A and U+017F name files that Windows keeps distinct from "k" and
		// "s"; a Unicode case fold would merge them and admit a sibling.
		{name: "kelvin sign is a distinct name", got: mapper.SamePath("C:\\wor\u212a", `C:\work`), want: false},
		{name: "long s is a distinct name", got: mapper.SamePath("C:\\\u017f", `C:\s`), want: false},
		{name: "embedded nul fails closed", got: mapper.Contains(`C:\Work`, "C:\\Work\x00\\sub"), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("%s = %t, want %t", test.name, test.got, test.want)
			}
		})
	}
}

func TestRemoteRootsProjectsWindowsRoots(t *testing.T) {
	mapper := NewMapper()
	roots, err := mapper.RemoteRoots([]string{`C:\a\b`, `\\nas\share\proj`, `C:/a/b`, `c:\A\B`})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/c/a/b", "/unc/nas/share/proj", "/c/A/B"}
	if strings.Join(roots, "|") != strings.Join(want, "|") {
		t.Fatalf("RemoteRoots = %#v, want %#v", roots, want)
	}
}
