package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/multiformats/go-multiaddr"
)

// RelayServer holds the relay server state
type RelayServer struct {
	host      host.Host
	ctx       context.Context
	cancel    context.CancelFunc
	startTime time.Time

	// Stats
	mu               sync.RWMutex
	totalConnections int64
	peersConnected   map[peer.ID]time.Time
}

// Stats represents server statistics
type Stats struct {
	PeerID           string      `json:"peer_id"`
	Uptime           string      `json:"uptime"`
	UptimeSeconds    float64     `json:"uptime_seconds"`
	ConnectedPeers   int         `json:"connected_peers"`
	TotalConnections int64       `json:"total_connections"`
	Addresses        []string    `json:"addresses"`
	RelayAddresses   []string    `json:"relay_addresses"`
	Peers            []PeerStats `json:"peers"`
}

// PeerStats represents connected peer info
type PeerStats struct {
	ID           string   `json:"id"`
	ConnectedFor string   `json:"connected_for"`
	Addresses    []string `json:"addresses"`
}

func main() {
	// Get ports from environment (Render sets PORT)
	httpPort := os.Getenv("PORT")
	if httpPort == "" {
		httpPort = "8080"
	}

	p2pPort := os.Getenv("P2P_PORT")
	if p2pPort == "" {
		p2pPort = "4001"
	}

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create relay server
	server, err := NewRelayServer(ctx, p2pPort)
	if err != nil {
		fmt.Printf("Failed to create relay server: %v\n", err)
		os.Exit(1)
	}

	// Start HTTP server for health checks and stats
	go startHTTPServer(httpPort, server)

	// Print startup info
	printStartupInfo(server, httpPort)

	// Wait for shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
	server.Stop()
}

func NewRelayServer(ctx context.Context, port string) (*RelayServer, error) {
	ctx, cancel := context.WithCancel(ctx)

	// Generate private key (or load from env for persistence)
	var privKey crypto.PrivKey
	var err error

	privKeyHex := os.Getenv("PRIVATE_KEY")
	if privKeyHex != "" {
		// Decode existing key
		keyBytes, err := crypto.ConfigDecodeKey(privKeyHex)
		if err == nil {
			privKey, err = crypto.UnmarshalPrivateKey(keyBytes)
			if err != nil {
				fmt.Printf("Warning: Could not unmarshal private key, generating new one\n")
				privKey = nil
			}
		}
	}

	if privKey == nil {
		privKey, _, err = crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}

		// Print the key so it can be saved
		keyBytes, _ := crypto.MarshalPrivateKey(privKey)
		encoded := crypto.ConfigEncodeKey(keyBytes)
		fmt.Printf("\n🔑 Generated new private key. Save this to PRIVATE_KEY env var for persistence:\n%s\n\n", encoded)
	}

	// Listen addresses
	listenAddrs := []multiaddr.Multiaddr{}

	// TCP
	tcpAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", port))
	listenAddrs = append(listenAddrs, tcpAddr)

	// QUIC (optional, for better performance)
	quicAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/udp/%s/quic-v1", port))
	listenAddrs = append(listenAddrs, quicAddr)

	// Create host with relay service
	h, err := libp2p.New(
		libp2p.ListenAddrs(listenAddrs...),
		libp2p.Identity(privKey),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.EnableRelayService(
			relay.WithResources(relay.Resources{
				MaxReservations:        256,
				MaxCircuits:            32,
				BufferSize:             4096,
				MaxReservationsPerPeer: 8,
				MaxReservationsPerIP:   16,
				ReservationTTL:         time.Hour,
			}),
		),
		libp2p.ForceReachabilityPublic(),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create host: %w", err)
	}

	server := &RelayServer{
		host:           h,
		ctx:            ctx,
		cancel:         cancel,
		startTime:      time.Now(),
		peersConnected: make(map[peer.ID]time.Time),
	}

	// Set up connection notifications
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			server.mu.Lock()
			server.totalConnections++
			server.peersConnected[conn.RemotePeer()] = time.Now()
			server.mu.Unlock()

			fmt.Printf("✅ Peer connected: %s from %s\n",
				conn.RemotePeer().String()[:16],
				conn.RemoteMultiaddr().String())
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			server.mu.Lock()
			delete(server.peersConnected, conn.RemotePeer())
			server.mu.Unlock()

			fmt.Printf("❌ Peer disconnected: %s\n", conn.RemotePeer().String()[:16])
		},
	})

	return server, nil
}

func (s *RelayServer) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		PeerID:           s.host.ID().String(),
		Uptime:           time.Since(s.startTime).Round(time.Second).String(),
		UptimeSeconds:    time.Since(s.startTime).Seconds(),
		ConnectedPeers:   len(s.peersConnected),
		TotalConnections: s.totalConnections,
		Addresses:        []string{},
		RelayAddresses:   []string{},
		Peers:            []PeerStats{},
	}

	// Get addresses
	for _, addr := range s.host.Addrs() {
		stats.Addresses = append(stats.Addresses, addr.String())
		relayAddr := fmt.Sprintf("%s/p2p/%s", addr.String(), s.host.ID().String())
		stats.RelayAddresses = append(stats.RelayAddresses, relayAddr)
	}

	// Get connected peers
	for peerID, connTime := range s.peersConnected {
		peerStats := PeerStats{
			ID:           peerID.String(),
			ConnectedFor: time.Since(connTime).Round(time.Second).String(),
			Addresses:    []string{},
		}

		// Get peer addresses
		for _, addr := range s.host.Network().Peerstore().Addrs(peerID) {
			peerStats.Addresses = append(peerStats.Addresses, addr.String())
		}

		stats.Peers = append(stats.Peers, peerStats)
	}

	return stats
}

func (s *RelayServer) Stop() error {
	s.cancel()
	return s.host.Close()
}

func startHTTPServer(port string, server *RelayServer) {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"peer_id": server.host.ID().String(),
		})
	})

	// Detailed stats endpoint
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(server.GetStats())
	})

	// Root endpoint with instructions
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		stats := server.GetStats()

		html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>libp2p Relay Server</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #eee; }
        .container { background: #16213e; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h1 { color: #00d9ff; margin-bottom: 10px; }
        h2 { color: #ff6b6b; margin-top: 30px; }
        .status { display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .status.online { background: #00c853; color: white; }
        pre { background: #0f0f23; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 14px; }
        code { color: #00d9ff; }
        .peer-id { font-family: monospace; background: #0f0f23; padding: 10px; border-radius: 5px; word-break: break-all; }
        .relay-addr { font-family: monospace; font-size: 12px; background: #0f0f23; padding: 8px; margin: 5px 0; border-radius: 3px; word-break: break-all; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-box { background: #0f3460; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; color: #00d9ff; }
        .stat-label { font-size: 12px; color: #aaa; margin-top: 5px; }
        .endpoint { background: #0f0f23; padding: 10px; margin: 5px 0; border-radius: 5px; }
        .method { color: #00c853; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔄 libp2p Relay Server</h1>
        <span class="status online">● Online</span>

        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-value">%d</div>
                <div class="stat-label">Connected Peers</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">%d</div>
                <div class="stat-label">Total Connections</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">%s</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>

        <h2>📍 Peer ID</h2>
        <div class="peer-id">%s</div>

        <h2>🔗 Relay Addresses</h2>
        <p>Use these addresses to connect your peers:</p>
        %s

        <h2>🧪 Test Connection</h2>
        <p>Run this command to test the relay:</p>
        <pre><code>go run test_peer.go -relay "%s"</code></pre>

        <h2>📡 API Endpoints</h2>
        <div class="endpoint"><span class="method">GET</span> <code>/health</code> - Health check</div>
        <div class="endpoint"><span class="method">GET</span> <code>/stats</code> - Detailed statistics (JSON)</div>

        <h2>📖 Usage Example</h2>
        <pre><code>// Connect to this relay from your Go code:
relayAddr := "%s"

ma, _ := multiaddr.NewMultiaddr(relayAddr)
relayInfo, _ := peer.AddrInfoFromP2pAddr(ma)

// Connect and reserve
host.Connect(ctx, *relayInfo)
client.Reserve(ctx, host, *relayInfo)</code></pre>
    </div>
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>`,
			stats.ConnectedPeers,
			stats.TotalConnections,
			stats.Uptime,
			stats.PeerID,
			formatRelayAddrs(stats.RelayAddresses),
			getFirstRelayAddr(stats.RelayAddresses),
			getFirstRelayAddr(stats.RelayAddresses),
		)

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	})

	fmt.Printf("🌐 HTTP server starting on port %s\n", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Printf("HTTP server error: %v\n", err)
	}
}

func formatRelayAddrs(addrs []string) string {
	html := ""
	for _, addr := range addrs {
		html += fmt.Sprintf(`<div class="relay-addr">%s</div>`, addr)
	}
	return html
}

func getFirstRelayAddr(addrs []string) string {
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

func printStartupInfo(server *RelayServer, httpPort string) {
	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║           🚀 LIBP2P RELAY SERVER STARTED                   ║")
	fmt.Println("╠════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Peer ID: %s...     ║\n", server.host.ID().String()[:20])
	fmt.Printf("║ HTTP Port: %-47s ║\n", httpPort)
	fmt.Println("╠════════════════════════════════════════════════════════════╣")
	fmt.Println("║ 📍 Relay Addresses:                                        ║")

	for _, addr := range server.host.Addrs() {
		fullAddr := fmt.Sprintf("%s/p2p/%s", addr, server.host.ID())
		if len(fullAddr) > 56 {
			fmt.Printf("║ %s... ║\n", fullAddr[:53])
		} else {
			fmt.Printf("║ %-58s ║\n", fullAddr)
		}
	}

	fmt.Println("╠════════════════════════════════════════════════════════════╣")
	fmt.Println("║ 🔗 Endpoints:                                              ║")
	fmt.Println("║   GET /        - Web dashboard                             ║")
	fmt.Println("║   GET /health  - Health check                              ║")
	fmt.Println("║   GET /stats   - JSON statistics                           ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
}
