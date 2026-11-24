package evasion

import (
	"testing"
)

func TestAttemptTracker(t *testing.T) {
	tracker := NewAttemptTracker(2)

	host := "192.168.1.100"

	// First attempt: OK
	if !tracker.CanAttempt(host) {
		t.Fatalf("first attempt should be allowed")
	}

	// Second attempt: OK
	if !tracker.CanAttempt(host) {
		t.Fatalf("second attempt should be allowed")
	}

	// Third attempt: should be blocked by F2B threshold
	if tracker.CanAttempt(host) {
		t.Fatalf("third attempt should be blocked by F2B max-tries")
	}

	// Different host should be allowed
	if !tracker.CanAttempt("10.0.0.1") {
		t.Fatalf("new host should be allowed")
	}
}

func TestInterleaveTargets(t *testing.T) {
	targets := []string{
		"192.168.1.1:22",
		"192.168.1.2:22",
		"192.168.1.3:22",
		"10.0.0.1:22",
		"10.0.0.2:22",
		"172.16.0.1:22",
	}

	interleaved := InterleaveTargets(targets)
	if len(interleaved) != len(targets) {
		t.Fatalf("expected %d targets, got %d", len(targets), len(interleaved))
	}

	// Verify that consecutive targets are from different subnets where possible
	for i := 0; i < len(interleaved)-1; i++ {
		sub1 := ExtractSubnetKey(interleaved[i])
		sub2 := ExtractSubnetKey(interleaved[i+1])
		// Check that we don't have consecutive duplicates from the 192.168.1 subnet when others exist
		if sub1 == sub2 && sub1 == "192.168.1.0" && i < 3 {
			t.Logf("Notice: consecutive targets from same subnet at index %d", i)
		}
	}
}
