package triage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"phantom-ssh/pkg/honeypot"
)

func TestResultWriter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "phantom_triage_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rw, err := NewResultWriter(tmpDir)
	if err != nil {
		t.Fatalf("failed to create result writer: %v", err)
	}

	probe := &honeypot.ShellProbeResult{
		IsRoot:   true,
		OSName:   "Ubuntu 22.04 LTS",
		CPUCores: "8",
		RAMMB:    "32768",
		GPUInfo:  "NVIDIA A100-SXM4-40GB",
	}

	rw.RecordGood("192.168.1.10:22", "root", "secret", probe, 45*time.Millisecond)

	// Check goods.txt
	goodsData, err := os.ReadFile(filepath.Join(tmpDir, "goods.txt"))
	if err != nil || !strings.Contains(string(goodsData), "192.168.1.10:22:root:secret") {
		t.Fatalf("goods.txt missing expected entry: %v", string(goodsData))
	}

	// Check root.txt
	rootData, err := os.ReadFile(filepath.Join(tmpDir, "root.txt"))
	if err != nil || !strings.Contains(string(rootData), "[ROOT | Ubuntu 22.04 LTS") {
		t.Fatalf("root.txt missing expected entry: %v", string(rootData))
	}

	// Check gpu.txt
	gpuData, err := os.ReadFile(filepath.Join(tmpDir, "gpu.txt"))
	if err != nil || !strings.Contains(string(gpuData), "NVIDIA A100") {
		t.Fatalf("gpu.txt missing expected entry: %v", string(gpuData))
	}

	// Check high_ram.txt
	ramData, err := os.ReadFile(filepath.Join(tmpDir, "high_ram.txt"))
	if err != nil || !strings.Contains(string(ramData), "32768 MB") {
		t.Fatalf("high_ram.txt missing expected entry: %v", string(ramData))
	}

	// Check detailed.txt
	detailedData, err := os.ReadFile(filepath.Join(tmpDir, "detailed.txt"))
	if err != nil || !strings.Contains(string(detailedData), "PHANTOM-SSH HIT") {
		t.Fatalf("detailed.txt missing expected entry: %v", string(detailedData))
	}
}
