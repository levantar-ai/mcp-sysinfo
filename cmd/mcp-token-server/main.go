package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/tokenserver"
)

func main() {
	// Subcommands
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			serveCmd()
			return
		case "client":
			clientCmd()
			return
		case "rotate":
			rotateCmd()
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}

	// Default to serve
	serveCmd()
}

func printUsage() {
	fmt.Print(`MCP Token Server - JWT issuer for MCP authentication

USAGE:
    mcp-token-server [COMMAND] [OPTIONS]

COMMANDS:
    serve       Start the token server (default)
    client      Manage client registrations
    rotate      Manually rotate signing keys
    help        Show this help message

SERVE OPTIONS:
    --config <path>     Path to config file (JSON)
    --listen <addr>     Listen address (default: 127.0.0.1:8444)
    --issuer <url>      Token issuer URL
    --audience <name>   Token audience (default: mcp-sysinfo)
    --key-dir <path>    Directory for key storage
    --clients <path>    Path to clients JSON file

CLIENT SUBCOMMANDS:
    client add [--clients <file>] [--scopes <s1,s2,...>] <id> <name>
    client list [--clients <file>]
    client remove [--clients <file>] <id>

EXAMPLES:
    # Start server with defaults
    mcp-token-server serve

    # Start with config file
    mcp-token-server serve --config /etc/mcp-token-server/config.json

    # Add a client
    mcp-token-server client add myapp "My Application" --scopes core,logs

    # Get a token (using curl)
    curl -X POST http://localhost:8444/token \
        -u myapp:SECRET \
        -d "scope=core logs"

ENDPOINTS:
    GET  /.well-known/jwks.json   Public keys for token verification
    POST /token                    Request a new token
    GET  /health                   Server health check

For MCP Server configuration, see SECURITY.md.
`)
}

func serveCmd() {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file")
	listen := fs.String("listen", "", "Listen address")
	issuer := fs.String("issuer", "", "Token issuer URL")
	audience := fs.String("audience", "", "Token audience")
	keyDir := fs.String("key-dir", "", "Key storage directory")
	clientsFile := fs.String("clients", "", "Clients file path")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file")
	tlsKey := fs.String("tls-key", "", "TLS key file")

	fs.Parse(os.Args[2:])

	// Load config
	var cfg *tokenserver.Config
	var err error

	if *configPath != "" {
		cfg, err = tokenserver.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	} else {
		cfg = tokenserver.DefaultConfig()
	}

	// Override from flags
	if *listen != "" {
		cfg.ListenAddr = *listen
	}
	if *issuer != "" {
		cfg.Issuer = *issuer
	}
	if *audience != "" {
		cfg.Audience = *audience
	}
	if *keyDir != "" {
		cfg.KeyDir = *keyDir
	}
	if *clientsFile != "" {
		cfg.ClientsFile = *clientsFile
	}
	if *tlsCert != "" {
		cfg.TLSCert = *tlsCert
	}
	if *tlsKey != "" {
		cfg.TLSKey = *tlsKey
	}

	// Create and start server
	server, err := tokenserver.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating server: %v\n", err)
		os.Exit(1)
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	select {
	case err := <-errChan:
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	case sig := <-sigChan:
		fmt.Printf("\nReceived %s, shutting down...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Shutdown error: %v\n", err)
		}
	}
}

func clientCmd() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: mcp-token-server client <add|list|remove> [args]")
		os.Exit(1)
	}

	switch os.Args[2] {
	case "add":
		fs := flag.NewFlagSet("client-add", flag.ExitOnError)
		clientsFile := fs.String("clients", "clients.json", "Clients file path")
		scopesFlag := fs.String("scopes", "core", "Comma-separated scopes")
		fs.Parse(os.Args[3:])
		args := fs.Args()

		if len(args) < 2 {
			fmt.Println("Usage: mcp-token-server client add <id> <name> [--clients <file>] [--scopes <s1,s2>]")
			os.Exit(1)
		}

		clientID := args[0]
		clientName := args[1]
		scopes := splitScopes(*scopesFlag)

		cs, err := tokenserver.NewClientStore(*clientsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		secret, err := cs.AddClient(clientID, clientName, scopes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error adding client: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Client added successfully!\n\n")
		fmt.Printf("  Client ID:     %s\n", clientID)
		fmt.Printf("  Client Secret: %s\n", secret)
		fmt.Printf("  Scopes:        %v\n", scopes)
		fmt.Printf("\n⚠️  Save the secret now - it cannot be retrieved later.\n")

	case "list":
		fs := flag.NewFlagSet("client-list", flag.ExitOnError)
		clientsFile := fs.String("clients", "clients.json", "Clients file path")
		fs.Parse(os.Args[3:])

		cs, err := tokenserver.NewClientStore(*clientsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		clients := cs.ListClients()
		if len(clients) == 0 {
			fmt.Println("No clients registered.")
			return
		}

		fmt.Printf("%-20s %-30s %-10s %s\n", "ID", "NAME", "ENABLED", "SCOPES")
		fmt.Println(repeatStr("-", 80))
		for _, c := range clients {
			enabled := "yes"
			if !c.Enabled {
				enabled = "no"
			}
			fmt.Printf("%-20s %-30s %-10s %v\n", c.ID, c.Name, enabled, c.AllowedScopes)
		}

	case "remove":
		fs := flag.NewFlagSet("client-remove", flag.ExitOnError)
		clientsFile := fs.String("clients", "clients.json", "Clients file path")
		fs.Parse(os.Args[3:])
		args := fs.Args()

		if len(args) < 1 {
			fmt.Println("Usage: mcp-token-server client remove <id> [--clients <file>]")
			os.Exit(1)
		}

		cs, err := tokenserver.NewClientStore(*clientsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := cs.RemoveClient(args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "Error removing client: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Client '%s' removed.\n", args[0])

	default:
		fmt.Printf("Unknown client command: %s\n", os.Args[2])
		os.Exit(1)
	}
}

func rotateCmd() {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	keyDir := fs.String("key-dir", "", "Key storage directory (required)")
	fs.Parse(os.Args[2:])

	if *keyDir == "" {
		fmt.Println("Usage: mcp-token-server rotate --key-dir <path>")
		os.Exit(1)
	}

	km, err := tokenserver.NewKeyManager(*keyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading keys: %v\n", err)
		os.Exit(1)
	}

	if err := km.RotateKey(); err != nil {
		fmt.Fprintf(os.Stderr, "Error rotating key: %v\n", err)
		os.Exit(1)
	}

	_, kid := km.GetCurrentKey()
	fmt.Printf("Key rotated successfully. New KID: %s\n", kid)
}

func splitScopes(s string) []string {
	var scopes []string
	for _, scope := range splitStr(s, ",") {
		scope = trimSpace(scope)
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

func splitStr(s, sep string) []string {
	var result []string
	for len(s) > 0 {
		idx := indexStr(s, sep)
		if idx == -1 {
			result = append(result, s)
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	return result
}

func indexStr(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func repeatStr(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
