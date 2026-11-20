package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"strings"
	"testing"
)

const testRelease = "7.3.1-vole-kata430"

func gzipConfig(t *testing.T, plain string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func fixture(t *testing.T) (options, dependencies, map[string][]byte, *int) {
	t.Helper()
	var config strings.Builder
	for _, key := range requiredConfig {
		config.WriteString(key + "=y\n")
	}
	module := make([]byte, 24)
	copy(module, []byte{0x7f, 'E', 'L', 'F', 2, 1})
	module[18] = 183
	module = append(module, []byte("vermagic="+testRelease+" SMP mod_unload aarch64\x00~Module signature appended~\n")...)
	files := map[string][]byte{
		"/proc/config.gz":                                     gzipConfig(t, config.String()),
		"/proc/sys/kernel/random/boot_id":                     []byte("3bd1aa26-b24d-4184-95db-75ab9802522b\n"),
		"/proc/sys/net/mptcp/enabled":                         []byte("1\n"),
		"/proc/sys/net/ipv4/tcp_congestion_control":           []byte("bbr\n"),
		"/proc/sys/net/ipv4/tcp_available_congestion_control": []byte("reno bbr\n"),
		"/proc/sys/kernel/tainted":                            []byte("0\n"),
		"/module/brutal.ko":                                   module,
	}
	loads := new(int)
	deps := dependencies{
		os: "linux", arch: "arm64",
		readFile: func(path string) ([]byte, error) {
			if raw, ok := files[path]; ok {
				return raw, nil
			}
			return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
		},
		uname: func() (string, string, error) { return testRelease, "aarch64", nil },
		load: func(raw []byte) error {
			*loads++
			if !bytes.Equal(raw, files["/module/brutal.ko"]) {
				t.Fatal("loaded bytes differ from the frozen input")
			}
			files["/sys/module/brutal/version"] = []byte("2.0.1\n")
			files["/proc/sys/net/ipv4/tcp_available_congestion_control"] = []byte("reno bbr brutal\n")
			files["/proc/sys/kernel/tainted"] = []byte("4096\n") // External module O is allowed.
			return nil
		},
	}
	return options{module: "/module/brutal.ko", release: testRelease, brutalVersion: "2.0.1", defaultCC: "bbr"}, deps, files, loads
}

func TestManagedLoadAndFrozenConfigIdentity(t *testing.T) {
	opts, deps, files, loads := fixture(t)
	result := probe(opts, deps)
	if result.Status != "PASS" || !result.LoadedByProbe || *loads != 1 {
		t.Fatalf("unexpected result: %+v; loads=%d", result, *loads)
	}
	if result.Taint != 4096 || result.BrutalVersion != "2.0.1" || result.ModuleSHA256 != hash(files[opts.module]) {
		t.Fatalf("missing actual module evidence: %+v", result)
	}
	reader, err := gzip.NewReader(bytes.NewReader(files["/proc/config.gz"]))
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if _, err := plain.ReadFrom(reader); err != nil {
		t.Fatal(err)
	}
	if result.ConfigSHA256 != hash(plain.Bytes()) {
		t.Fatalf("config digest is not the raw decompressed bytes: %+v", result)
	}
}

func TestPreconditionsFailWithoutLoadingAndKeepRawEnvironment(t *testing.T) {
	cases := []struct {
		name   string
		change func(*options, *dependencies, map[string][]byte)
		want   string
	}{
		{"platform", func(_ *options, deps *dependencies, _ map[string][]byte) { deps.os = "darwin" }, "Linux arm64"},
		{"release", func(_ *options, deps *dependencies, _ map[string][]byte) {
			deps.uname = func() (string, string, error) { return "6.18.35", "aarch64", nil }
		}, "actual release"},
		{"rc", func(opts *options, _ *dependencies, _ map[string][]byte) { opts.release = "7.3.1-rc1" }, "stable 7.3"},
		{"machine", func(_ *options, deps *dependencies, _ map[string][]byte) {
			deps.uname = func() (string, string, error) { return testRelease, "x86_64", nil }
		}, "aarch64"},
		{"missing-config", func(_ *options, _ *dependencies, files map[string][]byte) { delete(files, "/proc/config.gz") }, "CONFIG_MODULE_SIG_FORCE"},
		{"disabled-mptcp", func(_ *options, _ *dependencies, files map[string][]byte) {
			files["/proc/sys/net/mptcp/enabled"] = []byte("0\n")
		}, "integer 1"},
		{"wrong-default", func(_ *options, _ *dependencies, files map[string][]byte) {
			files["/proc/sys/net/ipv4/tcp_congestion_control"] = []byte("reno\n")
		}, "before load"},
		{"forced-taint", func(_ *options, _ *dependencies, files map[string][]byte) {
			files["/proc/sys/kernel/tainted"] = []byte("2\n")
		}, "forced-module"},
		{"untrusted-taint", func(_ *options, _ *dependencies, files map[string][]byte) {
			files["/proc/sys/kernel/tainted"] = []byte("8192\n")
		}, "untrusted-signature"},
		{"unsigned", func(opts *options, _ *dependencies, files map[string][]byte) {
			files[opts.module] = files[opts.module][:30]
		}, "vermagic"},
		{"already-loaded", func(_ *options, _ *dependencies, files map[string][]byte) {
			files["/sys/module/brutal/version"] = []byte("2.0.1\n")
		}, "already loaded"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			opts, deps, files, loads := fixture(t)
			test.change(&opts, &deps, files)
			result := probe(opts, deps)
			if result.Status != "FAIL" || result.LoadedByProbe || *loads != 0 || !strings.Contains(result.Error, test.want) {
				t.Fatalf("unexpected result: %+v; loads=%d", result, *loads)
			}
			if test.name == "release" && (result.KernelRelease != "6.18.35" || result.DefaultCongestionControlBefore != "bbr") {
				t.Fatalf("actual failed environment was lost: %+v", result)
			}
		})
	}
}

func TestBorrowedCheckOnlyDoesNotLoad(t *testing.T) {
	opts, deps, files, loads := fixture(t)
	opts.checkOnly = true
	files["/sys/module/brutal/version"] = []byte("2.0.1\n")
	files["/proc/sys/net/ipv4/tcp_available_congestion_control"] = []byte("reno bbr brutal\n")
	result := probe(opts, deps)
	if result.Status != "PASS" || result.LoadedByProbe || *loads != 0 || result.BootID == "" {
		t.Fatalf("unexpected borrowed readback: %+v; loads=%d", result, *loads)
	}
	delete(files, "/sys/module/brutal/version")
	result = probe(opts, deps)
	if result.Status != "FAIL" || result.LoadedByProbe || *loads != 0 {
		t.Fatalf("missing borrowed module admitted: %+v; loads=%d", result, *loads)
	}
}

func TestDisabledSysctlPreventsModuleLoad(t *testing.T) {
	for _, disabled := range []string{"CONFIG_SYSCTL=n", "# CONFIG_SYSCTL is not set"} {
		t.Run(disabled, func(t *testing.T) {
			opts, deps, files, loads := fixture(t)
			var config strings.Builder
			for _, key := range requiredConfig {
				if key == "CONFIG_SYSCTL" {
					config.WriteString(disabled + "\n")
				} else {
					config.WriteString(key + "=y\n")
				}
			}
			files["/proc/config.gz"] = gzipConfig(t, config.String())
			result := probe(opts, deps)
			if result.Status != "FAIL" || result.Config["CONFIG_SYSCTL"] != "n" || result.LoadedByProbe || *loads != 0 || !strings.Contains(result.Error, "CONFIG_SYSCTL must equal y") {
				t.Fatalf("disabled SYSCTL admitted module load: %+v; loads=%d", result, *loads)
			}
		})
	}
}

func TestDisabledBasicModuleVersionProfilePreventsLoad(t *testing.T) {
	for _, option := range []string{"CONFIG_MODVERSIONS", "CONFIG_BASIC_MODVERSIONS"} {
		for _, disabled := range []string{option + "=n", "# " + option + " is not set"} {
			t.Run(disabled, func(t *testing.T) {
				opts, deps, files, loads := fixture(t)
				var config strings.Builder
				for _, key := range requiredConfig {
					if key == option {
						config.WriteString(disabled + "\n")
					} else {
						config.WriteString(key + "=y\n")
					}
				}
				files["/proc/config.gz"] = gzipConfig(t, config.String())
				result := probe(opts, deps)
				if result.Status != "FAIL" || result.Config[option] != "n" || result.LoadedByProbe || *loads != 0 || !strings.Contains(result.Error, option+" must equal y") {
					t.Fatalf("disabled Basic module version profile admitted load: %+v; loads=%d", result, *loads)
				}
			})
		}
	}
}

func TestFailedLoadAndChangedPostStateFail(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string][]byte) error
		want   string
		loaded bool
	}{
		{"load-error", func(_ map[string][]byte) error { return errors.New("signature rejected") }, "signature rejected", false},
		{"version", func(files map[string][]byte) error {
			files["/sys/module/brutal/version"] = []byte("2.0.0\n")
			return nil
		}, "actual Brutal version", true},
		{"default", func(files map[string][]byte) error {
			files["/proc/sys/net/ipv4/tcp_congestion_control"] = []byte("brutal\n")
			return nil
		}, "default congestion control changed", true},
		{"taint", func(files map[string][]byte) error { files["/proc/sys/kernel/tainted"] = []byte("12288\n"); return nil }, "untrusted-signature", true},
		{"changed-file", func(files map[string][]byte) error { files["/module/brutal.ko"] = []byte("different file"); return nil }, "module file changed", true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			opts, deps, files, _ := fixture(t)
			originalLoad := deps.load
			deps.load = func(raw []byte) error {
				if test.name == "load-error" {
					return test.change(files)
				}
				if err := originalLoad(raw); err != nil {
					return err
				}
				return test.change(files)
			}
			result := probe(opts, deps)
			if result.Status != "FAIL" || result.LoadedByProbe != test.loaded || !strings.Contains(result.Error, test.want) {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestConfigAndModuleInputValidation(t *testing.T) {
	config, digest, err := configFromGzip(gzipConfig(t, "# CONFIG_MPTCP is not set\nCONFIG_MODULES=y\n"))
	if err != nil || config["CONFIG_MPTCP"] != "n" || config["CONFIG_MODULES"] != "y" || digest == "" {
		t.Fatalf("unexpected config: %v, %q, %v", config, digest, err)
	}
	if _, _, err := configFromGzip(gzipConfig(t, "CONFIG_MPTCP=y\n# CONFIG_MPTCP is not set\n")); err == nil {
		t.Fatal("duplicate configuration accepted")
	}
	opts, _, files, _ := fixture(t)
	module := files[opts.module]
	if err := validateModule(module, "7.3.0-other"); err == nil {
		t.Fatal("wrong release accepted")
	}
	if err := validateModule(module[:len(module)-1], testRelease); err == nil {
		t.Fatal("missing signature accepted")
	}
	for _, release := range []string{"7.4.0-rc1", "7.3.1-rc1", "6.18.35", "7.3", "7.3.1\n"} {
		if stable73(release) {
			t.Fatalf("unstable or malformed release accepted: %q", release)
		}
	}
}
