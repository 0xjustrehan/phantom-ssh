package honeypot

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"phantom-ssh/pkg/stealth"

	"golang.org/x/crypto/ssh"
)

// Known honeypot banner fragments
var KnownHoneypotBanners = []string{
	"ssh-2.0-openssh_6.0p1 debian-4",
	"ssh-2.0-libssh_0.6.0",
	"ssh-2.0-openssh_5.1p1 debian-5",
	"ssh-2.0-openssh_5.9p1",
	"ssh-2.0-openssh_6.6.1p1",
	"cowrie",
	"kippo",
	"honssh",
	"honeytrap",
	"dionaea",
	"ssh-honeypot",
	"kojoney",
	"twisted.conch",
}

// Suspicious hostnames commonly hardcoded in honeypot configs
var SuspiciousHostnames = []string{
	"honeypot", "fake", "trap", "sandbox",
	"simulation", "decoy", "honey", "compute-node",
	"svr01", "nas01",
}

// HoneypotVerdict contains detection outcome
type HoneypotVerdict struct {
	IsHoneypot bool
	Score      int
	Reasons    []string
}

// CheckBanner analyzes the raw SSH banner string for known signatures
func CheckBanner(banner string) (score int, reasons []string) {
	lowerBanner := strings.ToLower(banner)

	for _, sig := range KnownHoneypotBanners {
		if strings.Contains(lowerBanner, sig) {
			score += 4
			reasons = append(reasons, fmt.Sprintf("Known honeypot banner: %s", sig))
			break
		}
	}

	// Obsolete SSH versions frequently used by static honeypots
	if strings.Contains(lowerBanner, "openssh_4.") ||
		strings.Contains(lowerBanner, "openssh_5.0") ||
		strings.Contains(lowerBanner, "dropbear_0.") {
		score += 2
		reasons = append(reasons, "Obsolete ancient SSH version")
	}

	return score, reasons
}

// CheckCanaryAuth probes if server accepts ANY password (universal honeypot trap)
func CheckCanaryAuth(target string, timeout time.Duration) bool {
	// Generate random 16-byte canary username and password
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	canaryUser := "chk_" + hex.EncodeToString(b)
	canaryPass := "Trap_Canary_" + hex.EncodeToString(b) + "!@#9"

	config := stealth.BuildClientConfig(canaryUser, canaryPass, "", timeout)

	conn, err := stealth.DialWithTimeout("tcp", target, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	c, chans, reqs, err := ssh.NewClientConn(conn, target, config)
	if err == nil {
		// Server accepted completely bogus credentials!
		_ = c.Close()
		go ssh.DiscardRequests(reqs)
		for range chans {
		}
		return true // Confirmed catch-all honeypot
	}

	return false
}

// ShellProbeResult holds results from the single-shot validation probe
type ShellProbeResult struct {
	RawOutput  string
	MathPassed bool
	UserID     string
	Username   string
	IsRoot     bool
	HasSudo    bool
	Kernel     string
	OSName     string
	CPUCores   string
	RAMMB      string
	GPUInfo    string
	DiskInfo   string
	IsRealProc bool
	IsCowrie   bool
}

// ExecuteVerificationPipeline runs a high-speed single-shot shell verification
func ExecuteVerificationPipeline(client *ssh.Client, timeout time.Duration) (*ShellProbeResult, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	// High-speed compound inspection pipeline
	probeScript := `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "===PHANTOM_BEGIN==="
echo "MATH:$((43981+21437))"
echo "ID:$(id -u 2>/dev/null):$(id -un 2>/dev/null)"
echo "SUDO:$(sudo -n true 2>/dev/null && echo YES || echo NO)"
echo "UNAME:$(uname -s -m -r 2>/dev/null)"
echo "OS:$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo "CPU:$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null)"
echo "RAM:$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || grep MemTotal /proc/meminfo 2>/dev/null | awk '{print int($2/1024)}')"
echo "GPU:$(lspci 2>/dev/null | grep -Ei 'vga|3d|display|nvidia|amd|tesla' | head -1)"
echo "DISK:$(df -h / 2>/dev/null | awk 'NR==2 {print $2 "/" $4}')"
echo "PROCFS:$(test -f /proc/version && echo REAL || echo MOCK)"
echo "COWRIE:$(cat /proc/mounts /proc/version 2>/dev/null | grep -i cowrie || echo CLEAN)"
echo "===PHANTOM_END==="
`

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- session.Run(probeScript)
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("probe timed out after %v", timeout)
	case err := <-done:
		// Even if exit status != 0, examine stdout
		raw := stdout.String()
		if len(raw) == 0 && err != nil {
			return nil, err
		}
		return parseProbeOutput(raw), nil
	}
}

// parseProbeOutput parses the delimited verification output
func parseProbeOutput(raw string) *ShellProbeResult {
	res := &ShellProbeResult{
		RawOutput: raw,
		CPUCores:  "1",
		RAMMB:     "Unknown",
		OSName:    "Linux",
		Kernel:    "Unknown",
	}

	// Check for ANSI terminal clear codes (Cowrie signature)
	if strings.Contains(raw, "\x1b[H\x1b[J") || strings.Contains(raw, "\x1b[2J") {
		res.IsCowrie = true
	}

	lines := strings.Split(raw, "\n")
	inside := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "===PHANTOM_BEGIN===" {
			inside = true
			continue
		}
		if line == "===PHANTOM_END===" {
			inside = false
			break
		}
		if !inside {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		key := parts[0]
		val := strings.TrimSpace(parts[1])

		switch key {
		case "MATH":
			// 43981 + 21437 = 65418
			if val == "65418" {
				res.MathPassed = true
			}
		case "ID":
			idParts := strings.Split(val, ":")
			if len(idParts) >= 1 {
				res.UserID = idParts[0]
				if res.UserID == "0" {
					res.IsRoot = true
				}
			}
			if len(idParts) >= 2 {
				res.Username = idParts[1]
			}
		case "SUDO":
			if val == "YES" {
				res.HasSudo = true
			}
		case "UNAME":
			res.Kernel = val
		case "OS":
			if val != "" {
				res.OSName = val
			}
		case "CPU":
			if val != "" && val != "0" {
				res.CPUCores = val
			}
		case "RAM":
			if val != "" && val != "0" {
				res.RAMMB = val
			}
		case "GPU":
			res.GPUInfo = val
		case "DISK":
			res.DiskInfo = val
		case "PROCFS":
			if val == "REAL" {
				res.IsRealProc = true
			}
		case "COWRIE":
			if val != "CLEAN" && strings.Contains(strings.ToLower(val), "cowrie") {
				res.IsCowrie = true
			}
		}
	}

	return res
}

// EvaluateHoneypot evaluates banner, canary, and shell probe to return final verdict
func EvaluateHoneypot(target string, banner string, probe *ShellProbeResult, canaryAccepted bool) *HoneypotVerdict {
	score := 0
	var reasons []string

	// 1. Canary check (automatic disqualification)
	if canaryAccepted {
		score += 10
		reasons = append(reasons, "Universal credential trap: server accepted random canary password")
	}

	// 2. Banner check
	bScore, bReasons := CheckBanner(banner)
	score += bScore
	reasons = append(reasons, bReasons...)

	// 3. Shell behavioral checks
	if probe != nil {
		// Shell parameter math evaluation check
		if !probe.MathPassed {
			score += 5
			reasons = append(reasons, "Failed POSIX shell arithmetic $((43981+21437)) (Python/Mock shell)")
		}

		// ANSI screen clearing codes
		if probe.IsCowrie {
			score += 5
			reasons = append(reasons, "Cowrie ANSI terminal codes or procfs signature detected")
		}

		// Missing /proc
		if !probe.IsRealProc {
			score += 2
			reasons = append(reasons, "Missing or mock /proc/version")
		}

		// Known static Cowrie kernel / OS signatures
		lowerKernel := strings.ToLower(probe.Kernel)
		if strings.Contains(lowerKernel, "3.2.0-4-amd64") ||
			strings.Contains(lowerKernel, "debian 3.2.68-1+deb7u6") {
			score += 3
			reasons = append(reasons, "Static Cowrie Debian kernel 3.2.0-4-amd64 signature")
		}
	}

	threshold := 4
	isHoneypot := score >= threshold

	return &HoneypotVerdict{
		IsHoneypot: isHoneypot,
		Score:      score,
		Reasons:    reasons,
	}
}

// QuickSocketCheck verifies if host is an Endlessh / Tarpit daemon
func CheckIfTarpit(target string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Wait up to 2 seconds for SSH banner
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return true // Read deadline expired without standard banner -> Tarpit
	}

	header := string(buf[:n])
	// Valid SSH banner must begin with "SSH-"
	if !strings.HasPrefix(header, "SSH-") {
		return true
	}

	return false
}
