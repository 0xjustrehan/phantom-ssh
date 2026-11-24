package stealth

import (
	"crypto/rand"
	"math/big"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Realistic OpenSSH client version strings to avoid "SSH-2.0-Go" signatures
var RealisticClientVersions = []string{
	"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.3",
	"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
	"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
	"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
	"SSH-2.0-OpenSSH_9.0p1",
	"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
	"SSH-2.0-OpenSSH_8.0p1",
}

// Realistic OpenSSH ciphers matching modern Linux clients
var PreferredCiphers = []string{
	"chacha20-poly1305@openssh.com",
	"aes128-gcm@openssh.com",
	"aes256-gcm@openssh.com",
	"aes128-ctr",
	"aes192-ctr",
	"aes256-ctr",
}

// Preferred Key Exchange algorithms
var PreferredKeyExchanges = []string{
	"curve25519-sha256",
	"curve25519-sha256@libssh.org",
	"ecdh-sha2-nistp256",
	"ecdh-sha2-nistp384",
	"diffie-hellman-group14-sha256",
}

// Preferred MACs
var PreferredMACs = []string{
	"hmac-sha2-256-etm@openssh.com",
	"hmac-sha2-512-etm@openssh.com",
	"hmac-sha2-256",
	"hmac-sha2-512",
}

// GetRandomClientVersion picks a realistic OpenSSH client banner
func GetRandomClientVersion() string {
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(RealisticClientVersions))))
	if err != nil {
		return RealisticClientVersions[0]
	}
	return RealisticClientVersions[idx.Int64()]
}

// BuildClientConfig creates a hardened, stealthy SSH client configuration
func BuildClientConfig(user, password, clientVersion string, timeout time.Duration) *ssh.ClientConfig {
	if clientVersion == "" {
		clientVersion = GetRandomClientVersion()
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
		ClientVersion:   clientVersion,
		Config: ssh.Config{
			Ciphers:      PreferredCiphers,
			KeyExchanges: PreferredKeyExchanges,
			MACs:         PreferredMACs,
		},
	}
}

// DialWithTimeout performs TCP dial with strict deadline to neutralize SSH tarpits (e.g. Endlessh)
func DialWithTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	// Apply read/write deadlines during SSH handshake
	_ = conn.SetDeadline(time.Now().Add(timeout * 2))
	return conn, nil
}
