package runtime

import (
	"os"
	"testing"
)

// fakeCodexBannerEnv selects the fake Codex CLI built into this test binary.
// The runtime resolves its Codex binary through appserver.VerifyVersion, which
// executes the configured path directly, so the fixture has to be an executable
// image: Windows cannot launch a shebang script, and a .cmd shim is refused by
// design because it would run Codex one process generation away from the
// Connector-owned job object. The test binary is already an image on every
// platform, so it doubles as the fake CLI rather than needing a compiler.
const fakeCodexBannerEnv = "SUB2API_FAKE_CODEX_VERSION_BANNER"

func TestMain(m *testing.M) {
	if banner := os.Getenv(fakeCodexBannerEnv); banner != "" {
		_, _ = os.Stdout.WriteString(banner)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeCodexBinary returns a Codex binary path that answers --version with
// banner. The environment is inherited by the app-server child, so the
// selection reaches the fake without the caller passing arguments through
// appserver, which fixes the --version argument list.
func fakeCodexBinary(t *testing.T, banner string) string {
	t.Helper()
	image, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	t.Setenv(fakeCodexBannerEnv, banner)
	return image
}
