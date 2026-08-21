//go:build !windows

package appserver

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeFakeCodex(t *testing.T, contents string) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "fake-codex")
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	return script
}

func fakeCodexVersion(t *testing.T, stdout, stderr string) string {
	t.Helper()
	contents := "#!/bin/sh\n"
	if stderr != "" {
		contents += "printf '%b' " + fmt.Sprintf("%q", stderr) + " >&2\n"
	}
	contents += "printf '%b' " + fmt.Sprintf("%q", stdout) + "\n"
	return writeFakeCodex(t, contents)
}

func fakeCodexBootstrap(t *testing.T) string {
	t.Helper()
	return writeFakeCodex(t, `#!/bin/sh
if test "$1" = "--version"; then
  printf '%s\n' 'codex-cli 0.147.0'
  exit 0
fi
test "$1" = "app-server" || exit 41
test "$2" = "--listen" || exit 42
test "$3" = "stdio://" || exit 43
IFS= read -r initialize || exit 44
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"codexHome":"/tmp/fake-codex-home","platformFamily":"unix","platformOs":"linux","userAgent":"fake"}}'
IFS= read -r initialized || exit 45
printf '%s\n' '{"jsonrpc":"2.0","method":"turn/started","params":{"threadId":"t","turn":{"id":"turn-1","items":[],"status":"inProgress"}},"emittedAtMs":1785945600000}'
IFS= read -r request || exit 46
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"data":[{"id":"model","model":"model","displayName":"Model","description":"Test model","isDefault":true,"hidden":false,"defaultReasoningEffort":"medium","supportedReasoningEfforts":[]}]}}'
while :; do sleep 1; done
`)
}

func fakeCodexRevalidation(t *testing.T, audit, drifted string) string {
	t.Helper()
	return writeFakeCodex(t, fmt.Sprintf(`#!/bin/sh
if test "$1" = "--version"; then
  printf 'version\n' >> %q
  if test -f %q; then
    printf 'codex-cli 9.9.9\n'
  else
    printf 'codex-cli 0.147.0\n'
  fi
  exit 0
fi
printf 'app-server\n' >> %q
IFS= read -r initialize || exit 40
printf '%%s\n' '{"jsonrpc":"2.0","id":1,"result":{"codexHome":"/tmp/fake-codex-home","platformFamily":"unix","platformOs":"linux","userAgent":"fake"}}'
IFS= read -r initialized || exit 41
while :; do sleep 1; done
`, audit, drifted, audit))
}

func fakeCodexStderrLeak(t *testing.T, diagnostic string) string {
	t.Helper()
	return writeFakeCodex(t, fmt.Sprintf(`#!/bin/sh
if test "$1" = "--version"; then
  printf '%%s\n' 'codex-cli 0.147.0'
  exit 0
fi
IFS= read -r initialize || exit 40
printf '%%s\n' '{"jsonrpc":"2.0","id":1,"result":{"codexHome":"/tmp/fake-codex-home","platformFamily":"unix","platformOs":"linux","userAgent":"fake"}}'
IFS= read -r initialized || exit 41
printf '%%b' %q >&2
exit 23
`, diagnostic))
}

func fakeCodexE2E(t *testing.T, dir, source string) string {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "codex")
	if err := os.WriteFile(binary, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	return binary
}
