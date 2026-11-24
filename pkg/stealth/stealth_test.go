package stealth

import (
	"strings"
	"testing"
	"time"
)

func TestStealthClientConfig(t *testing.T) {
	config := BuildClientConfig("root", "toor", "", 3*time.Second)

	if config.ClientVersion == "" {
		t.Fatalf("ClientVersion should not be empty")
	}

	if config.ClientVersion == "SSH-2.0-Go" {
		t.Fatalf("Default Go SSH client version must NOT be exposed!")
	}

	if !strings.HasPrefix(config.ClientVersion, "SSH-2.0-OpenSSH_") {
		t.Fatalf("Expected OpenSSH client version, got %s", config.ClientVersion)
	}

	if len(config.Config.Ciphers) == 0 {
		t.Fatalf("Expected custom ciphers list")
	}

	if len(config.Config.KeyExchanges) == 0 {
		t.Fatalf("Expected custom key exchange list")
	}
}
