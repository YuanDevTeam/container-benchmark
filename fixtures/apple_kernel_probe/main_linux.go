package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const maxInputBytes = 8 << 20

var requiredConfig = []string{
	"CONFIG_MPTCP", "CONFIG_MPTCP_IPV6", "CONFIG_MODULES",
	"CONFIG_MODULE_UNLOAD", "CONFIG_MODULE_SIG", "CONFIG_MODULE_SIG_FORCE", "CONFIG_SYSCTL",
	"CONFIG_MODVERSIONS", "CONFIG_BASIC_MODVERSIONS",
}

type options struct {
	module, release, brutalVersion, defaultCC string
	checkOnly                                 bool
}

type observation struct {
	SchemaVersion                  int               `json:"schemaVersion"`
	Status                         string            `json:"status"`
	KernelRelease                  string            `json:"kernelRelease"`
	Architecture                   string            `json:"architecture"`
	BootID                         string            `json:"bootID"`
	Config                         map[string]string `json:"config"`
	ConfigSHA256                   string            `json:"configSHA256"`
	MPTCPEnabled                   int               `json:"mptcpEnabled"`
	DefaultCongestionControlBefore string            `json:"defaultCongestionControlBefore"`
	DefaultCongestionControlAfter  string            `json:"defaultCongestionControlAfter"`
	AvailableCongestionControl     []string          `json:"availableCongestionControl"`
	BrutalVersion                  string            `json:"brutalVersion"`
	ModuleSHA256                   string            `json:"moduleSHA256"`
	LoadedByProbe                  bool              `json:"loadedByProbe"`
	Taint                          int               `json:"taint"`
	Error                          string            `json:"error"`
}

type dependencies struct {
	readFile func(string) ([]byte, error)
	uname    func() (release, machine string, err error)
	load     func([]byte) error
	os, arch string
}

func hash(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func configFromGzip(raw []byte) (map[string]string, string, error) {
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, "", err
	}
	defer reader.Close()
	plain, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(plain) > maxInputBytes {
		return nil, "", errors.New("decompressed kernel config exceeds size bound")
	}
	config := make(map[string]string)
	for _, key := range requiredConfig {
		for _, line := range strings.Split(string(plain), "\n") {
			if value, ok := strings.CutPrefix(line, key+"="); ok {
				if _, duplicate := config[key]; duplicate {
					return config, hash(plain), fmt.Errorf("duplicate kernel config %s", key)
				}
				config[key] = value
			} else if line == "# "+key+" is not set" {
				if _, duplicate := config[key]; duplicate {
					return config, hash(plain), fmt.Errorf("duplicate kernel config %s", key)
				}
				config[key] = "n"
			}
		}
	}
	return config, hash(plain), nil
}

func validateModule(raw []byte, release string) error {
	if len(raw) < 20 || len(raw) > maxInputBytes || !bytes.Equal(raw[:6], []byte{0x7f, 'E', 'L', 'F', 2, 1}) {
		return errors.New("module must be a bounded little-endian ELF64 input")
	}
	if binary.LittleEndian.Uint16(raw[18:20]) != 183 {
		return errors.New("module must be ARM64")
	}
	start := bytes.Index(raw, []byte("vermagic="))
	if start < 0 {
		return errors.New("module has no vermagic")
	}
	value := raw[start+len("vermagic="):]
	end := bytes.IndexByte(value, 0)
	if end < 0 || !strings.HasPrefix(string(value[:end]), release+" ") {
		return errors.New("module vermagic differs from the expected kernel")
	}
	if !bytes.HasSuffix(raw, []byte("~Module signature appended~\n")) {
		return errors.New("module signature trailer is missing")
	}
	return nil
}

func stable73(release string) bool {
	return regexp.MustCompile(`^7\.3\.[0-9]+([+-][A-Za-z0-9._+-]+)?$`).MatchString(release) &&
		!strings.Contains(strings.ToLower(release), "rc")
}

func probe(opts options, deps dependencies) observation {
	result := observation{SchemaVersion: 1, Status: "FAIL", Architecture: deps.arch,
		Config: make(map[string]string), AvailableCongestionControl: []string{}}
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }
	read := func(path string) string {
		raw, err := deps.readFile(path)
		if err != nil {
			fail("read %s: %v", path, err)
			return ""
		}
		return strings.TrimSpace(string(raw))
	}
	finish := func() observation {
		if len(failures) == 0 {
			result.Status = "PASS"
		} else {
			result.Error = strings.Join(failures, "; ")
		}
		return result
	}
	if deps.os != "linux" || deps.arch != "arm64" {
		fail("probe requires Linux arm64, got %s/%s", deps.os, deps.arch)
		return finish()
	}
	release, machine, err := deps.uname()
	result.KernelRelease = release
	if err != nil {
		fail("uname: %v", err)
	}
	if machine != "aarch64" {
		fail("uname machine must be aarch64, got %q", machine)
	}
	if !stable73(opts.release) || result.KernelRelease != opts.release {
		fail("actual release %q must equal expected stable 7.3 release %q", result.KernelRelease, opts.release)
	}
	if opts.brutalVersion != "2.0.1" || opts.defaultCC != "bbr" {
		fail("required Brutal version/default congestion control are 2.0.1/bbr")
	}
	result.BootID = read("/proc/sys/kernel/random/boot_id")
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(result.BootID) {
		fail("invalid boot ID")
	}
	configBytes, err := deps.readFile("/proc/config.gz")
	if err != nil {
		fail("read /proc/config.gz: %v", err)
	} else {
		config, digest, configErr := configFromGzip(configBytes)
		if config != nil {
			result.Config = config
		}
		result.ConfigSHA256 = digest
		if configErr != nil {
			fail("kernel config: %v", configErr)
		}
	}
	for _, key := range requiredConfig {
		if result.Config[key] != "y" {
			fail("%s must equal y, got %q", key, result.Config[key])
		}
	}
	mptcpText := read("/proc/sys/net/mptcp/enabled")
	result.MPTCPEnabled, err = strconv.Atoi(mptcpText)
	if err != nil || result.MPTCPEnabled != 1 {
		fail("MPTCP enabled must equal integer 1, got %q", mptcpText)
	}
	result.DefaultCongestionControlBefore = read("/proc/sys/net/ipv4/tcp_congestion_control")
	if result.DefaultCongestionControlBefore != opts.defaultCC {
		fail("default congestion control before load must equal %s", opts.defaultCC)
	}
	result.AvailableCongestionControl = strings.Fields(read("/proc/sys/net/ipv4/tcp_available_congestion_control"))
	taintText := read("/proc/sys/kernel/tainted")
	result.Taint, err = strconv.Atoi(taintText)
	if err != nil || result.Taint < 0 {
		fail("invalid taint value %q", taintText)
	}
	if result.Taint&((1<<1)|(1<<13)) != 0 {
		fail("kernel has forced-module or untrusted-signature taint")
	}
	moduleBytes, err := deps.readFile(opts.module)
	if err != nil {
		fail("read module: %v", err)
	} else {
		result.ModuleSHA256 = hash(moduleBytes)
		if err := validateModule(moduleBytes, opts.release); err != nil {
			fail("module: %v", err)
		}
	}
	priorVersion, versionErr := deps.readFile("/sys/module/brutal/version")
	if versionErr == nil {
		result.BrutalVersion = strings.TrimSpace(string(priorVersion))
		if !opts.checkOnly {
			fail("Brutal is already loaded; this probe cannot prove artifact ownership")
		}
	} else if opts.checkOnly || !os.IsNotExist(versionErr) {
		fail("read existing Brutal version: %v", versionErr)
	}
	// Never change the guest after any identity, configuration or ownership failure.
	if len(failures) == 0 && !opts.checkOnly {
		if err := deps.load(moduleBytes); err != nil {
			fail("init_module: %v", err)
		} else {
			result.LoadedByProbe = true
		}
	}
	result.DefaultCongestionControlAfter = read("/proc/sys/net/ipv4/tcp_congestion_control")
	result.AvailableCongestionControl = strings.Fields(read("/proc/sys/net/ipv4/tcp_available_congestion_control"))
	if version, err := deps.readFile("/sys/module/brutal/version"); err == nil {
		result.BrutalVersion = strings.TrimSpace(string(version))
	} else {
		fail("read loaded Brutal version: %v", err)
	}
	taintText = read("/proc/sys/kernel/tainted")
	result.Taint, err = strconv.Atoi(taintText)
	if err != nil || result.Taint < 0 {
		fail("invalid final taint value %q", taintText)
	}
	if result.DefaultCongestionControlAfter != opts.defaultCC || result.DefaultCongestionControlAfter != result.DefaultCongestionControlBefore {
		fail("default congestion control changed or is not %s", opts.defaultCC)
	}
	if !contains(result.AvailableCongestionControl, "brutal") {
		fail("Brutal congestion algorithm is not registered")
	}
	if result.BrutalVersion != opts.brutalVersion {
		fail("actual Brutal version %q differs from %q", result.BrutalVersion, opts.brutalVersion)
	}
	if result.Taint&((1<<1)|(1<<13)) != 0 {
		fail("kernel has forced-module or untrusted-signature taint")
	}
	if finalBytes, err := deps.readFile(opts.module); err != nil {
		fail("read module after probe: %v", err)
	} else if hash(finalBytes) != result.ModuleSHA256 {
		fail("module file changed during probe")
	}
	return finish()
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// These syscall numbers are the Linux ARM64 ABI; probe rejects every other platform.
func linuxUname() (string, string, error) {
	var fields [6][65]byte
	_, _, errno := syscall.Syscall(160, uintptr(unsafe.Pointer(&fields[0][0])), 0, 0)
	if errno != 0 {
		return "", "", errno
	}
	cString := func(raw []byte) string {
		if end := bytes.IndexByte(raw, 0); end >= 0 {
			return string(raw[:end])
		}
		return string(raw)
	}
	return cString(fields[2][:]), cString(fields[4][:]), nil
}

func initModule(raw []byte) error {
	if len(raw) == 0 {
		return errors.New("empty module")
	}
	parameters := [1]byte{0}
	_, _, errno := syscall.Syscall(105, uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&parameters[0])))
	runtime.KeepAlive(raw)
	if errno != 0 {
		return errno
	}
	return nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxInputBytes {
		return nil, fmt.Errorf("%s exceeds input size bound", path)
	}
	return raw, nil
}

func main() {
	var opts options
	flag.StringVar(&opts.module, "module", "", "matching signed ARM64 Brutal module")
	flag.StringVar(&opts.release, "release", "", "exact expected stable 7.3 kernel release")
	flag.StringVar(&opts.brutalVersion, "brutal-version", "2.0.1", "required Brutal version")
	flag.StringVar(&opts.defaultCC, "default-cc", "bbr", "required unchanged default congestion control")
	flag.BoolVar(&opts.checkOnly, "check-only", false, "read an already-loaded module without loading it")
	flag.Parse()
	result := probe(opts, dependencies{readFile: readBounded, uname: linuxUname, load: initModule, os: runtime.GOOS, arch: runtime.GOARCH})
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if result.Status != "PASS" {
		os.Exit(1)
	}
}
