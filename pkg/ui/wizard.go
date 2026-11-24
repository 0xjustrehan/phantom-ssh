package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"phantom-ssh/pkg/engine"
)

// RunInteractiveWizard prompts the operator through setup when no flags are supplied
func RunInteractiveWizard() (*engine.Config, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n\033[36;1m================================================================")
	fmt.Println("       ⚡ PHANTOM-SSH v1.0.0 — Interactive Configuration")
	fmt.Println("================================================================\033[0m")

	cfg := &engine.Config{
		Timeout:         3 * time.Second,
		Workers:         100,
		MaxTriesPerHost: 2,
		Interleave:      true,
		CanaryCheck:     true,
		AutoTriage:      true,
		OutputDir:       "./results",
	}

	// 1. Target file detection
	defaultTarget := "SSH.txt"
	if _, err := os.Stat("SSH.txt"); os.IsNotExist(err) {
		defaultTarget = "targets.txt"
	}
	fmt.Printf("\n[?] Target file (IP or IP:PORT) [%s]: ", defaultTarget)
	tInput, _ := reader.ReadString('\n')
	tInput = strings.TrimSpace(tInput)
	if tInput == "" {
		tInput = defaultTarget
	}
	cfg.TargetFile = tInput

	// 2. Credential Mode
	fmt.Println("\n[+] Select Credential Input Mode:")
	fmt.Println("    1) Combo file (e.g. user:pass)")
	fmt.Println("    2) Split Users file + Passwords file")
	fmt.Println("    3) Single Credential (e.g. root:root)")
	fmt.Print("[?] Select option [1]: ")
	modeInput, _ := reader.ReadString('\n')
	modeInput = strings.TrimSpace(modeInput)
	if modeInput == "" {
		modeInput = "1"
	}

	switch modeInput {
	case "1":
		fmt.Print("[?] Combo file path [combos.txt]: ")
		cInput, _ := reader.ReadString('\n')
		cInput = strings.TrimSpace(cInput)
		if cInput == "" {
			cInput = "combos.txt"
		}
		cfg.ComboFile = cInput
	case "2":
		fmt.Print("[?] Users file path [users.txt]: ")
		uInput, _ := reader.ReadString('\n')
		cfg.UserFile = strings.TrimSpace(uInput)
		if cfg.UserFile == "" {
			cfg.UserFile = "users.txt"
		}

		fmt.Print("[?] Passwords file path [passwords.txt]: ")
		pInput, _ := reader.ReadString('\n')
		cfg.PassFile = strings.TrimSpace(pInput)
		if cfg.PassFile == "" {
			cfg.PassFile = "passwords.txt"
		}
	case "3":
		fmt.Print("[?] Target Username [root]: ")
		uInput, _ := reader.ReadString('\n')
		cfg.SingleUser = strings.TrimSpace(uInput)
		if cfg.SingleUser == "" {
			cfg.SingleUser = "root"
		}

		fmt.Print("[?] Target Password [root]: ")
		pInput, _ := reader.ReadString('\n')
		cfg.SinglePass = strings.TrimSpace(pInput)
		if cfg.SinglePass == "" {
			cfg.SinglePass = "root"
		}
	default:
		cfg.ComboFile = "combos.txt"
	}

	// 3. Workers
	fmt.Print("\n[?] Concurrency Workers [100]: ")
	wInput, _ := reader.ReadString('\n')
	wInput = strings.TrimSpace(wInput)
	if wInput != "" {
		if w, err := strconv.Atoi(wInput); err == nil && w > 0 {
			cfg.Workers = w
		}
	}

	// 4. Timeout
	fmt.Print("[?] Socket & Auth Timeout in seconds [3]: ")
	toInput, _ := reader.ReadString('\n')
	toInput = strings.TrimSpace(toInput)
	if toInput != "" {
		if to, err := strconv.Atoi(toInput); err == nil && to > 0 {
			cfg.Timeout = time.Duration(to) * time.Second
		}
	}

	// 5. Fail2ban Max Tries
	fmt.Print("[?] Max Attempts Per Host to evade Fail2ban [2]: ")
	f2bInput, _ := reader.ReadString('\n')
	f2bInput = strings.TrimSpace(f2bInput)
	if f2bInput != "" {
		if maxT, err := strconv.Atoi(f2bInput); err == nil && maxT >= 0 {
			cfg.MaxTriesPerHost = maxT
		}
	}

	// 6. Subnet Interleaving
	fmt.Print("[?] Enable Subnet /24 Interleaving for anti-IDS evasion (Y/n) [Y]: ")
	ilInput, _ := reader.ReadString('\n')
	ilInput = strings.TrimSpace(strings.ToLower(ilInput))
	if ilInput == "n" || ilInput == "no" {
		cfg.Interleave = false
	}

	// 7. Output directory
	fmt.Print("[?] Results Output Directory [./results]: ")
	outInput, _ := reader.ReadString('\n')
	outInput = strings.TrimSpace(outInput)
	if outInput != "" {
		cfg.OutputDir = outInput
	}

	fmt.Println("\n\033[32;1m[+] Configuration initialized. Launching phantom-ssh engine...\033[0m")
	time.Sleep(500 * time.Millisecond)

	return cfg, nil
}
