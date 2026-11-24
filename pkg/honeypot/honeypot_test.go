package honeypot

import (
	"testing"
)

func TestCheckBanner(t *testing.T) {
	cowrieBanner := "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
	score, reasons := CheckBanner(cowrieBanner)
	if score < 4 {
		t.Fatalf("expected honeypot score >= 4, got %d", score)
	}
	if len(reasons) == 0 {
		t.Fatalf("expected reasons to be non-empty")
	}

	cleanBanner := "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.3"
	cleanScore, _ := CheckBanner(cleanBanner)
	if cleanScore != 0 {
		t.Fatalf("clean banner should have 0 score, got %d", cleanScore)
	}
}

func TestParseProbeOutputRealLinux(t *testing.T) {
	raw := `===PHANTOM_BEGIN===
MATH:65418
ID:0:root
SUDO:YES
UNAME:Linux 6.2.0-39-generic x86_64
OS:Ubuntu 22.04.3 LTS
CPU:16
RAM:32140
GPU:NVIDIA Corporation GA102 [GeForce RTX 3090]
DISK:1.8T/1.2T
PROCFS:REAL
COWRIE:CLEAN
===PHANTOM_END===`

	probe := parseProbeOutput(raw)
	if !probe.MathPassed {
		t.Fatalf("math check should have passed")
	}
	if !probe.IsRoot {
		t.Fatalf("root detection failed")
	}
	if !probe.HasSudo {
		t.Fatalf("sudo detection failed")
	}
	if probe.CPUCores != "16" {
		t.Fatalf("expected 16 cores, got %s", probe.CPUCores)
	}
	if probe.RAMMB != "32140" {
		t.Fatalf("expected 32140 RAM, got %s", probe.RAMMB)
	}
	if probe.GPUInfo == "" {
		t.Fatalf("GPU info should not be empty")
	}

	verdict := EvaluateHoneypot("192.168.1.50:22", "SSH-2.0-OpenSSH_9.3p1", probe, false)
	if verdict.IsHoneypot {
		t.Fatalf("real Linux system should not be classified as honeypot: score %d", verdict.Score)
	}
}

func TestParseProbeOutputFakeCowrie(t *testing.T) {
	// Cowrie failing math and containing ANSI reset codes
	raw := "\x1b[H\x1b[J" + `===PHANTOM_BEGIN===
MATH:$((43981+21437))
ID:1000:user
SUDO:NO
UNAME:Linux 3.2.0-4-amd64 x86_64
OS:Debian GNU/Linux 7 (wheezy)
CPU:1
RAM:1024
GPU:
DISK:20G/15G
PROCFS:MOCK
COWRIE:twisted.conch.cowrie
===PHANTOM_END===`

	probe := parseProbeOutput(raw)
	if probe.MathPassed {
		t.Fatalf("math check should have failed on mock shell")
	}
	if !probe.IsCowrie {
		t.Fatalf("cowrie ANSI/signature should have been detected")
	}

	verdict := EvaluateHoneypot("1.2.3.4:22", "SSH-2.0-OpenSSH_6.0p1 Debian-4", probe, false)
	if !verdict.IsHoneypot {
		t.Fatalf("Cowrie mock shell must be detected as honeypot")
	}
}
