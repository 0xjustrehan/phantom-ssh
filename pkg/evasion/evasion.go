package evasion

import (
	"crypto/rand"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// AttemptTracker tracks attempts per host to enforce Fail2ban evasion thresholds
type AttemptTracker struct {
	mu       sync.Mutex
	attempts map[string]int
	maxTries int
}

// NewAttemptTracker creates a new attempt tracker
func NewAttemptTracker(maxTries int) *AttemptTracker {
	return &AttemptTracker{
		attempts: make(map[string]int),
		maxTries: maxTries,
	}
}

// CanAttempt checks if a host can be probed and increments attempt count
func (at *AttemptTracker) CanAttempt(host string) bool {
	if at.maxTries <= 0 {
		return true // Unlimited
	}

	at.mu.Lock()
	defer at.mu.Unlock()

	count := at.attempts[host]
	if count >= at.maxTries {
		return false
	}

	at.attempts[host] = count + 1
	return true
}

// RecordSuccess marks a host as successfully logged in
func (at *AttemptTracker) RecordSuccess(host string) {
	at.mu.Lock()
	defer at.mu.Unlock()
	// Set to high value so no further attempts are made
	at.attempts[host] = 999999
}

// GetAttempts returns attempt count for a host
func (at *AttemptTracker) GetAttempts(host string) int {
	at.mu.Lock()
	defer at.mu.Unlock()
	return at.attempts[host]
}

// ExtractSubnetKey returns /24 for IPv4 or /48 for IPv6
func ExtractSubnetKey(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Fallback to string split
		parts := strings.Split(ipStr, ".")
		if len(parts) >= 3 {
			return parts[0] + "." + parts[1] + "." + parts[2]
		}
		return ipStr
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		// Return /24
		return net.IPv4(ipv4[0], ipv4[1], ipv4[2], 0).String()
	}

	// IPv6: return /48
	mask := net.CIDRMask(48, 128)
	return ip.Mask(mask).String()
}

// InterleaveTargets distributes targets across /24 subnets to prevent subnet-level IDS alerts
func InterleaveTargets(targets []string) []string {
	if len(targets) <= 2 {
		return targets
	}

	// Group targets by subnet
	buckets := make(map[string][]string)
	var keys []string

	for _, t := range targets {
		host, _, err := net.SplitHostPort(t)
		if err != nil {
			host = t
		}
		subnet := ExtractSubnetKey(host)
		if len(buckets[subnet]) == 0 {
			keys = append(keys, subnet)
		}
		buckets[subnet] = append(buckets[subnet], t)
	}

	// Shuffle bucket keys
	for i := len(keys) - 1; i > 0; i-- {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := int(n.Int64())
		keys[i], keys[j] = keys[j], keys[i]
	}

	// Round-robin pull from each bucket
	result := make([]string, 0, len(targets))
	for {
		added := false
		for _, k := range keys {
			if len(buckets[k]) > 0 {
				result = append(result, buckets[k][0])
				buckets[k] = buckets[k][1:]
				added = true
			}
		}
		if !added {
			break
		}
	}

	return result
}

// ApplyJitter sleeps a random duration between 0 and maxJitterMs
func ApplyJitter(maxJitterMs int) {
	if maxJitterMs <= 0 {
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxJitterMs)))
	if err == nil && n.Int64() > 0 {
		time.Sleep(time.Duration(n.Int64()) * time.Millisecond)
	}
}
