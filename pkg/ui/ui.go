package ui

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"phantom-ssh/pkg/engine"
	"phantom-ssh/pkg/honeypot"
)

// UI manages the terminal output and dashboard
type UI struct {
	mu         sync.Mutex
	noTUI      bool
	quiet      bool
	recentHits []string
	stopChan   chan struct{}
}

// NewUI creates a new UI manager
func NewUI(noTUI, quiet bool) *UI {
	return &UI{
		noTUI:    noTUI,
		quiet:    quiet,
		stopChan: make(chan struct{}),
	}
}

// AddHit records a hit for display in the live dashboard
func (u *UI) AddHit(target, user, pass string, isHoneypot bool, probe *honeypot.ShellProbeResult, rtt time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()

	var line string
	if isHoneypot {
		line = fmt.Sprintf("\033[33m[🍯 HONEYPOT]\033[0m %s | %s:%s | Fake Shell / Emulated", target, user, pass)
	} else {
		meta := "Linux"
		if probe != nil {
			priv := "USER"
			if probe.IsRoot {
				priv = "\033[31;1mROOT\033[0m"
			} else if probe.HasSudo {
				priv = "\033[33;1mSUDO\033[0m"
			}

			hardware := fmt.Sprintf("%sC / %sMB", probe.CPUCores, probe.RAMMB)
			if probe.GPUInfo != "" {
				hardware += " / GPU"
			}
			meta = fmt.Sprintf("%s | %s | %s | %s", priv, probe.OSName, hardware, rtt.Round(time.Millisecond))
		}
		line = fmt.Sprintf("\033[32;1m[✅ HIT]\033[0m %s | %s:%s | %s", target, user, pass, meta)
	}

	if u.noTUI {
		fmt.Println(line)
		return
	}

	u.recentHits = append(u.recentHits, line)
	if len(u.recentHits) > 8 {
		u.recentHits = u.recentHits[1:]
	}
}

// StartDashboard runs the live refreshing TUI loop
func (u *UI) StartDashboard(eng *engine.Engine) {
	if u.noTUI || u.quiet {
		return
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-u.stopChan:
				return
			case <-ticker.C:
				u.render(eng)
			}
		}
	}()
}

// StopDashboard stops the dashboard refresh loop and prints summary
func (u *UI) StopDashboard(eng *engine.Engine) {
	if u.noTUI || u.quiet {
		return
	}
	close(u.stopChan)
	u.render(eng)
	fmt.Println("\n\033[32;1m[*] Scan Complete / Engine Stopped.\033[0m")
}

func (u *UI) render(eng *engine.Engine) {
	st := eng.GetStats()
	elapsed := time.Since(st.StartTime).Seconds()

	var rate float64
	var etaStr string = "calculating..."
	if elapsed > 0 && st.CompletedTasks > 0 {
		rate = float64(st.CompletedTasks) / elapsed
		if rate > 0 && st.TotalTasks > st.CompletedTasks {
			remainingSecs := float64(st.TotalTasks-st.CompletedTasks) / rate
			etaStr = formatDuration(time.Duration(remainingSecs) * time.Second)
		} else if st.CompletedTasks >= st.TotalTasks {
			etaStr = "00:00:00"
		}
	}

	pct := 0.0
	if st.TotalTasks > 0 {
		pct = float64(st.CompletedTasks) / float64(st.TotalTasks) * 100.0
		if pct > 100.0 {
			pct = 100.0
		}
	}

	const boxWidth = 76
	var sb strings.Builder

	// Clear screen & home cursor
	sb.WriteString("\033[H\033[2J")

	// Header Box
	sb.WriteString("╔" + strings.Repeat("═", boxWidth) + "╗\n")
	sb.WriteString(centerText("⚡ PHANTOM-SSH v1.0.0 — Elite Stealth SSH Sprayer & Triager ⚡", boxWidth) + "\n")
	sb.WriteString("╠" + strings.Repeat("═", boxWidth) + "╣\n")

	// Status Line
	status := fmt.Sprintf(" Elapsed: %s | ETA: %s | Speed: %.1f checks/s",
		formatDuration(time.Since(st.StartTime)), etaStr, rate)
	sb.WriteString(padLine(status, boxWidth) + "\n")

	// Progress Bar
	barWidth := 40
	completedSlots := int(math.Round((pct / 100.0) * float64(barWidth)))
	if completedSlots > barWidth {
		completedSlots = barWidth
	}
	bar := strings.Repeat("█", completedSlots) + strings.Repeat("░", barWidth-completedSlots)
	progLine := fmt.Sprintf(" [%s] %5.1f%% (%d / %d)", bar, pct, st.CompletedTasks, st.TotalTasks)
	sb.WriteString(padLine(progLine, boxWidth) + "\n")

	sb.WriteString("╠" + strings.Repeat("═", boxWidth) + "╣\n")

	// Metrics Line
	metricsLine := fmt.Sprintf(" ✅ Goods: %d | 🍯 Honeypots: %d | ❌ Fails: %d | 🛡️ F2B Guarded: %d",
		st.Goods, st.Honeypots, st.Errors, st.SkippedF2B)
	sb.WriteString(padLine(metricsLine, boxWidth) + "\n")

	sb.WriteString("╠" + strings.Repeat("═", boxWidth) + "╣\n")
	sb.WriteString(padLine(" 📡 Live Real-Time Hits & Telemetry:", boxWidth) + "\n")

	// Recent Hits Panel
	u.mu.Lock()
	hitsCopy := make([]string, len(u.recentHits))
	copy(hitsCopy, u.recentHits)
	u.mu.Unlock()

	if len(hitsCopy) == 0 {
		sb.WriteString(padLine("   (Listening for authenticated shells & responses...)", boxWidth) + "\n")
	} else {
		for _, h := range hitsCopy {
			sb.WriteString("║ " + truncateANSI(h, boxWidth-2) + "\n")
		}
	}

	sb.WriteString("╚" + strings.Repeat("═", boxWidth) + "╝\n")
	sb.WriteString("\033[90m [Ctrl+C] Gracefully Stop | Results saved in output directory\033[0m\n")

	fmt.Print(sb.String())
}

func padLine(s string, width int) string {
	plainLen := len(stripANSI(s))
	pad := width - plainLen - 2
	if pad < 0 {
		pad = 0
	}
	return "║ " + s + strings.Repeat(" ", pad) + " ║"
}

func centerText(s string, width int) string {
	plainLen := len(stripANSI(s))
	left := (width - plainLen) / 2
	right := width - plainLen - left
	if left < 0 {
		left = 0
	}
	if right < 0 {
		right = 0
	}
	return "║" + strings.Repeat(" ", left) + s + strings.Repeat(" ", right) + "║"
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func stripANSI(str string) string {
	var b strings.Builder
	inEsc := false
	for i := 0; i < len(str); i++ {
		if str[i] == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if str[i] == 'm' {
				inEsc = false
			}
			continue
		}
		b.WriteByte(str[i])
	}
	return b.String()
}

func truncateANSI(str string, maxLen int) string {
	plain := stripANSI(str)
	if len(plain) <= maxLen {
		return str + strings.Repeat(" ", maxLen-len(plain)) + "║"
	}
	return str[:maxLen-3] + "... ║"
}
