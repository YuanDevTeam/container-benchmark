package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type setupMemoryConn struct {
	net.Conn
	reader   *bytes.Reader
	writes   bytes.Buffer
	writeErr error
	closed   int
}

func (c *setupMemoryConn) Write(payload []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.writes.Write(payload)
}

func (c *setupMemoryConn) Close() error                     { c.closed++; return nil }
func (c *setupMemoryConn) Read(payload []byte) (int, error) { return c.reader.Read(payload) }
func (c *setupMemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *setupMemoryConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}
}
func (c *setupMemoryConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 42}
}

func TestDataSetupFailuresKeepTheirActualStage(t *testing.T) {
	for _, test := range []struct {
		name, phase string
		resolveErr  error
		dialErr     error
		writeErr    error
	}{
		{name: "TUN DNS timeout", phase: "TUN DNS", resolveErr: fixtureTimeout{}},
		{name: "data socket timeout", phase: "data connect", dialErr: fixtureTimeout{}},
		{name: "TCP hello timeout", phase: "TCP hello", writeErr: fixtureTimeout{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &setupMemoryConn{writeErr: test.writeErr}
			resolved, dialed := 0, 0
			resolve := func(name, expected string) error {
				resolved++
				if name != "fixture.invalid" || expected != "192.0.2.7" {
					t.Fatal("data setup changed the controlled DNS witness")
				}
				return test.resolveErr
			}
			dial := func(network, target string, timeout time.Duration) (net.Conn, error) {
				dialed++
				if resolved != 1 || network != "tcp" || target != "192.0.2.7:42" || timeout != 5*time.Second {
					t.Fatal("data socket bypassed DNS or changed the original timeout")
				}
				return conn, test.dialErr
			}
			got, err := dialDataWith(request{Transport: "tcp", TargetIP: "192.0.2.7"}, "fixture.invalid:42", resolve, dial)
			if got != nil || err == nil || dataSetupPhase(err) != test.phase || setupErrorKind(err) != "timeout" {
				t.Fatalf("wanted %q timeout, got conn=%v phase=%q kind=%q", test.phase, got, dataSetupPhase(err), setupErrorKind(err))
			}
			if test.resolveErr != nil && dialed != 0 {
				t.Fatal("failed TUN DNS still attempted a data socket")
			}
			if test.writeErr != nil && conn.closed != 1 {
				t.Fatal("failed TCP hello retained its acquired data connection")
			}
			if errors.Unwrap(err) == nil && test.phase != "data connect" {
				t.Fatal("stage classification lost the original failure")
			}
		})
	}
}

func TestPreparedFlowWaitsForSharedDecisionAndClosesWithoutBusinessStart(t *testing.T) {
	for _, failDNS := range []bool{false, true} {
		control := &setupMemoryConn{reader: bytes.NewReader([]byte("{\"port\":42}\n{\"ready\":true,\"source_verified\":true}\n"))}
		data := &setupMemoryConn{}
		var ready sync.WaitGroup
		ready.Add(1)
		prepared, start := make(chan flowResult, 1), make(chan bool)
		done := make(chan []flowResult, 1)
		go func() {
			done <- clientFlowWithIO("192.0.2.7:24003", request{Transport: "tcp", Seconds: 60}, &ready, start, prepared,
				func(string, string, time.Duration) (net.Conn, error) { return control, nil },
				func(request, string) (net.Conn, error) {
					if failDNS {
						return nil, &setupPhaseError{"TUN DNS", fixtureTimeout{}}
					}
					return data, nil
				})
		}()
		row := <-prepared
		ready.Wait()
		if failDNS {
			if row.Error != "TUN DNS" || row.SetupErrorKind != "timeout" {
				t.Fatal("DNS preparation failure lost its actual stage")
			}
		} else {
			select {
			case <-done:
				t.Fatal("successful setup closed before every flow was prepared")
			default:
			}
			if data.closed != 0 || row.SourceAddress == "" {
				t.Fatal("prepared data connection was not retained")
			}
		}
		close(start)
		<-done
		if len(prepared) != 0 || control.closed != 1 || (!failDNS && data.closed != 1) || strings.Contains(control.writes.String(), "\"start\"") {
			t.Fatal("preparation must report once, close/join and never start payload")
		}
	}
}

func TestClientPreparationGatesPressureAndPublishesRealCounts(t *testing.T) {
	for _, test := range []struct {
		name            string
		fail, setupOnly bool
	}{
		{"failed preparation", true, false}, {"prepare only", false, true}, {"ready pressure", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var joined, started atomic.Int32
			flow := func(_ string, r request, ready *sync.WaitGroup, start <-chan bool, prepared chan<- flowResult) []flowResult {
				row := flowResult{Transport: r.Transport, Direction: r.Direction, SourceVerified: true,
					SourceAddress: "192.0.2.1:40000", DestinationAddress: "192.0.2.7:42"}
				if test.fail && r.ExperienceFlow == 0 {
					row.Error, row.SetupErrorKind = "TUN DNS", "timeout"
					row.SourceAddress = ""
				}
				prepared <- row
				ready.Done()
				if row.Error == "" {
					if run, ok := <-start; ok && run {
						started.Add(1)
					}
				}
				joined.Add(1)
				return []flowResult{row}
			}
			root := t.TempDir()
			ready, start := filepath.Join(root, "ready"), filepath.Join(root, "start")
			if err := os.WriteFile(start, []byte("start\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err := runClientWith("192.0.2.7:24003", "mixed", "both", 60, 4, 1000, "", "", ready, start, test.setupOnly, flow, &output)
			if (err != nil) != test.fail || joined.Load() != 4 {
				t.Fatalf("preparation did not close/join all flows: %v", err)
			}
			wantStarts := int32(4)
			if test.fail || test.setupOnly {
				wantStarts = 0
			}
			if started.Load() != wantStarts {
				t.Fatal("failed or prepare-only run started pressure")
			}
			var proof struct {
				Flows       int
				Preparation preparationSummary
			}
			wire, err := os.ReadFile(ready)
			if err != nil || json.Unmarshal(wire, &proof) != nil {
				t.Fatal("missing preparation proof")
			}
			wantPrepared := 4
			if test.fail {
				wantPrepared = 3
			}
			if proof.Flows != 4 || proof.Preparation.PreparedFlows != wantPrepared || proof.Preparation.FailedFlows != 4-wantPrepared || proof.Preparation.Complete == test.fail {
				t.Fatal("ready proof used declared counts instead of actual outcomes")
			}
			var report struct {
				Phase       string
				Complete    bool
				Preparation preparationSummary
			}
			if json.Unmarshal(output.Bytes(), &report) != nil || report.Complete == test.fail || report.Preparation != proof.Preparation {
				t.Fatal("final report disagrees with preparation proof")
			}
			if (report.Phase == "prepare") != (test.fail || test.setupOnly) {
				t.Fatal("preparation was misreported as a pressure window")
			}
		})
	}
}

func TestMultiTargetUDPPreparationWaitsForTCPWithoutChangingBusinessBarrier(t *testing.T) {
	previousTargets := udpDestinations
	udpDestinations = 64
	t.Cleanup(func() { udpDestinations = previousTargets })
	tcpEntered, udpEntered := make(chan struct{}, 2), make(chan struct{}, 2)
	tcpReady := make(chan struct{})
	var starts, tcpPrepared, udpPrepared atomic.Int32
	flow := func(_ string, r request, ready *sync.WaitGroup, start <-chan bool, prepared chan<- flowResult) []flowResult {
		if r.Transport == "tcp" {
			tcpEntered <- struct{}{}
			<-tcpReady
			tcpPrepared.Add(1)
		} else {
			udpEntered <- struct{}{}
			if r.UDPDestinations == 64 {
				udpPrepared.Add(1)
			}
		}
		row := flowResult{Transport: r.Transport, Direction: r.Direction, SourceVerified: true,
			SourceAddress: "192.0.2.1:40000", DestinationAddress: "192.0.2.7:42"}
		prepared <- row
		ready.Done()
		if run, ok := <-start; ok && run {
			starts.Add(1)
		}
		return []flowResult{row}
	}
	root := t.TempDir()
	startFile := filepath.Join(root, "start")
	if err := os.WriteFile(startFile, []byte("start\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runClientWith("192.0.2.7:24003", "mixed", "both", 60, 4, 1000,
			"", "", filepath.Join(root, "ready"), startFile, false, flow, &output)
	}()
	for index := 0; index < 2; index++ {
		<-tcpEntered
	}
	earlyUDP := false
	select {
	case <-udpEntered:
		earlyUDP = true
	case <-time.After(50 * time.Millisecond):
	}
	earlyBusiness := starts.Load() != 0
	close(tcpReady)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("preparation did not join after TCP became ready")
	}
	if earlyUDP {
		t.Fatal("multi-target UDP hello preparation overlapped unfinished TCP preparation")
	}
	if earlyBusiness || starts.Load() != 4 || tcpPrepared.Load() != 2 || udpPrepared.Load() != 2 {
		t.Fatal("preparation changed transport counts or released business before all flows were ready")
	}
}

func TestPreparationProgressKeepsPartialSnapshotAndJoinsWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	p := newPreparationProgress(path, 3)
	defer p.close()
	tcp := &flowPreparation{owner: p, transport: "tcp"}
	udp := &flowPreparation{owner: p, transport: "udp"}
	pending := &flowPreparation{owner: p, transport: "udp"}
	tcp.stage("TUN DNS")
	tcp.finish(flowResult{Transport: "tcp", Error: "TUN DNS", SetupErrorKind: "timeout", DestinationAddress: "PRIVATE_ENDPOINT"})
	udp.stage("UDP hello")
	udp.stage("data readiness")
	udp.finish(flowResult{Transport: "udp", Error: "data readiness", SetupErrorKind: "origin-udp-hello-timeout",
		UDPHello: &originUDPHelloProgress{TargetIndex: 31, ReceivedTargets: 31, RequestedTargets: 64}})
	pending.stage("UDP hello")
	pending.stage("data readiness")
	if !p.close() {
		t.Fatal("snapshot publication failed")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64*1024 || strings.Contains(string(data), "PRIVATE") {
		t.Fatal("count snapshot missing, unbounded or retaining endpoint data")
	}
	var got preparationProgressState
	if json.Unmarshal(data, &got) != nil || got.RequestedFlows != 3 || got.CompletedFlows != 2 || got.PreparedFlows != 0 || got.FailedFlows != 2 || got.ActivePhases["udp"]["data readiness"] != 1 {
		t.Fatalf("lost partial preparation counts: %s", data)
	}
	if len(got.Errors) != 2 || got.UDPFailure == nil || got.UDPFailure.ReceivedTargets != 31 {
		t.Fatal("lost the origin UDP hello progress or classified setup failures")
	}
	if _, err := os.Stat(path + ".partial"); !os.IsNotExist(err) {
		t.Fatal("atomic publication retained a temporary snapshot")
	}
	pending.finish(flowResult{Transport: "udp"})
	if !p.close() {
		t.Fatal("snapshot publication failed")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("joined setup writer continued publishing")
	}
}

func TestOptionalPreparationProgressWriteFailureDoesNotBlockBusiness(t *testing.T) {
	before := preparationProgressFile
	preparationProgressFile = filepath.Join(t.TempDir(), "missing", "progress.json")
	t.Cleanup(func() { preparationProgressFile = before })
	var started atomic.Int32
	flow := func(_ string, r request, ready *sync.WaitGroup, start <-chan bool, prepared chan<- flowResult) []flowResult {
		row := flowResult{Transport: r.Transport, Direction: r.Direction, SourceVerified: true,
			SourceAddress: "192.0.2.1:40000", DestinationAddress: "192.0.2.7:42"}
		prepared <- row
		ready.Done()
		if run, ok := <-start; ok && run {
			started.Add(1)
		}
		return []flowResult{row}
	}
	var output bytes.Buffer
	if err := runClientWith("192.0.2.7:24003", "tcp", "up", 1, 2, 10, "", "", "", "", false, flow, &output); err != nil {
		t.Fatalf("optional snapshot prevented business start: %v", err)
	}
	var report struct {
		Complete  bool
		Available *bool `json:"preparation_progress_available"`
	}
	if json.Unmarshal(output.Bytes(), &report) != nil || !report.Complete || started.Load() != 2 || report.Available == nil || *report.Available {
		t.Fatal("missing optional-snapshot availability or joined business start")
	}
}
