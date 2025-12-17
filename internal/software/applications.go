// Package software provides software inventory and SBOM functionality.
package software

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// AppDefinition defines known application patterns for discovery.
type AppDefinition struct {
	Name        string
	Type        string
	ProcessName []string // Process names to look for
	ServiceName []string // Service names to look for
	Ports       []int    // Well-known ports
	ConfigPaths []string // Config file paths (can contain wildcards)
	LogPaths    []string // Log file paths (can contain wildcards)
	DataDir     string   // Data directory
	VersionCmd  []string // Command to get version: [cmd, args...]
}

// knownApplications defines well-known applications to detect.
var knownApplications = []AppDefinition{
	// Web Servers
	{Name: "nginx", Type: "web_server", ProcessName: []string{"nginx"}, ServiceName: []string{"nginx"}, Ports: []int{80, 443},
		ConfigPaths: []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*"},
		LogPaths:    []string{"/var/log/nginx/access.log", "/var/log/nginx/error.log"}, VersionCmd: []string{"nginx", "-v"}},
	{Name: "apache", Type: "web_server", ProcessName: []string{"apache2", "httpd"}, ServiceName: []string{"apache2", "httpd"}, Ports: []int{80, 443},
		ConfigPaths: []string{"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/apache2/sites-enabled/*"},
		LogPaths:    []string{"/var/log/apache2/access.log", "/var/log/apache2/error.log", "/var/log/httpd/access_log"}, VersionCmd: []string{"apache2", "-v"}},
	{Name: "caddy", Type: "web_server", ProcessName: []string{"caddy"}, ServiceName: []string{"caddy"}, Ports: []int{80, 443},
		ConfigPaths: []string{"/etc/caddy/Caddyfile", "/etc/caddy/*.json"}, LogPaths: []string{"/var/log/caddy/*.log"}, VersionCmd: []string{"caddy", "version"}},
	{Name: "tomcat", Type: "web_server", ProcessName: []string{"java"}, ServiceName: []string{"tomcat", "tomcat9", "tomcat8"}, Ports: []int{8080, 8443},
		ConfigPaths: []string{"/etc/tomcat*/server.xml", "/opt/tomcat/conf/server.xml"}, LogPaths: []string{"/var/log/tomcat*/*.log"}},
	// Databases
	{Name: "mysql", Type: "database", ProcessName: []string{"mysqld", "mariadbd"}, ServiceName: []string{"mysql", "mysqld", "mariadb"}, Ports: []int{3306},
		ConfigPaths: []string{"/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/*.cnf", "/etc/my.cnf"},
		LogPaths:    []string{"/var/log/mysql/error.log", "/var/log/mysql/*.log"}, DataDir: "/var/lib/mysql", VersionCmd: []string{"mysql", "--version"}},
	{Name: "postgresql", Type: "database", ProcessName: []string{"postgres", "postmaster"}, ServiceName: []string{"postgresql", "postgres"}, Ports: []int{5432},
		ConfigPaths: []string{"/etc/postgresql/*/main/postgresql.conf", "/var/lib/pgsql/data/postgresql.conf"},
		LogPaths:    []string{"/var/log/postgresql/*.log"}, DataDir: "/var/lib/postgresql", VersionCmd: []string{"psql", "--version"}},
	{Name: "mongodb", Type: "database", ProcessName: []string{"mongod", "mongos"}, ServiceName: []string{"mongod", "mongodb"}, Ports: []int{27017},
		ConfigPaths: []string{"/etc/mongod.conf", "/etc/mongodb.conf"},
		LogPaths:    []string{"/var/log/mongodb/mongod.log"}, DataDir: "/var/lib/mongodb", VersionCmd: []string{"mongod", "--version"}},
	{Name: "redis", Type: "database", ProcessName: []string{"redis-server"}, ServiceName: []string{"redis", "redis-server"}, Ports: []int{6379},
		ConfigPaths: []string{"/etc/redis/redis.conf", "/etc/redis.conf"},
		LogPaths:    []string{"/var/log/redis/redis-server.log"}, DataDir: "/var/lib/redis", VersionCmd: []string{"redis-server", "--version"}},
	{Name: "elasticsearch", Type: "database", ProcessName: []string{"java"}, ServiceName: []string{"elasticsearch"}, Ports: []int{9200, 9300},
		ConfigPaths: []string{"/etc/elasticsearch/elasticsearch.yml"},
		LogPaths:    []string{"/var/log/elasticsearch/*.log"}, DataDir: "/var/lib/elasticsearch", VersionCmd: []string{"curl", "-s", "localhost:9200"}},
	// Message Queues
	{Name: "rabbitmq", Type: "message_queue", ProcessName: []string{"beam.smp", "rabbitmq-server"}, ServiceName: []string{"rabbitmq-server"}, Ports: []int{5672, 15672},
		ConfigPaths: []string{"/etc/rabbitmq/rabbitmq.conf", "/etc/rabbitmq/rabbitmq-env.conf"},
		LogPaths:    []string{"/var/log/rabbitmq/*.log"}, DataDir: "/var/lib/rabbitmq", VersionCmd: []string{"rabbitmqctl", "version"}},
	{Name: "kafka", Type: "message_queue", ProcessName: []string{"java"}, ServiceName: []string{"kafka"}, Ports: []int{9092},
		ConfigPaths: []string{"/etc/kafka/server.properties", "/opt/kafka/config/server.properties"},
		LogPaths:    []string{"/var/log/kafka/*.log"}, DataDir: "/var/lib/kafka"},
	// Caching
	{Name: "memcached", Type: "cache", ProcessName: []string{"memcached"}, ServiceName: []string{"memcached"}, Ports: []int{11211},
		ConfigPaths: []string{"/etc/memcached.conf"}, LogPaths: []string{"/var/log/memcached.log"}, VersionCmd: []string{"memcached", "-h"}},
	{Name: "varnish", Type: "cache", ProcessName: []string{"varnishd"}, ServiceName: []string{"varnish"}, Ports: []int{6081, 6082},
		ConfigPaths: []string{"/etc/varnish/default.vcl"}, LogPaths: []string{"/var/log/varnish/*.log"}, VersionCmd: []string{"varnishd", "-V"}},
	// Runtimes
	{Name: "php-fpm", Type: "runtime", ProcessName: []string{"php-fpm"}, ServiceName: []string{"php-fpm", "php7.4-fpm", "php8.0-fpm", "php8.1-fpm", "php8.2-fpm"}, Ports: []int{9000},
		ConfigPaths: []string{"/etc/php/*/fpm/php-fpm.conf", "/etc/php-fpm.conf"},
		LogPaths:    []string{"/var/log/php*.log", "/var/log/php-fpm/*.log"}, VersionCmd: []string{"php", "-v"}},
	{Name: "nodejs", Type: "runtime", ProcessName: []string{"node", "nodejs"}, ServiceName: []string{},
		ConfigPaths: []string{}, LogPaths: []string{}, VersionCmd: []string{"node", "--version"}},
	// Containers
	{Name: "docker", Type: "container", ProcessName: []string{"dockerd"}, ServiceName: []string{"docker"}, Ports: []int{2375, 2376},
		ConfigPaths: []string{"/etc/docker/daemon.json"},
		LogPaths:    []string{"/var/log/docker.log"}, DataDir: "/var/lib/docker", VersionCmd: []string{"docker", "--version"}},
	{Name: "podman", Type: "container", ProcessName: []string{"podman"}, ServiceName: []string{"podman"},
		ConfigPaths: []string{"/etc/containers/containers.conf", "/etc/containers/registries.conf"},
		LogPaths:    []string{}, VersionCmd: []string{"podman", "--version"}},
	// Mail
	{Name: "postfix", Type: "mail", ProcessName: []string{"master"}, ServiceName: []string{"postfix"}, Ports: []int{25, 587},
		ConfigPaths: []string{"/etc/postfix/main.cf", "/etc/postfix/master.cf"},
		LogPaths:    []string{"/var/log/mail.log", "/var/log/maillog"}, DataDir: "/var/spool/postfix", VersionCmd: []string{"postconf", "-d", "mail_version"}},
	// Security
	{Name: "fail2ban", Type: "security", ProcessName: []string{"fail2ban-server"}, ServiceName: []string{"fail2ban"},
		ConfigPaths: []string{"/etc/fail2ban/fail2ban.conf", "/etc/fail2ban/jail.conf", "/etc/fail2ban/jail.local"},
		LogPaths:    []string{"/var/log/fail2ban.log"}, VersionCmd: []string{"fail2ban-server", "--version"}},
	// Directory
	{Name: "openldap", Type: "directory", ProcessName: []string{"slapd"}, ServiceName: []string{"slapd"}, Ports: []int{389, 636},
		ConfigPaths: []string{"/etc/ldap/ldap.conf", "/etc/openldap/ldap.conf"},
		LogPaths:    []string{"/var/log/slapd.log"}, DataDir: "/var/lib/ldap", VersionCmd: []string{"slapd", "-V"}},
}

// GetKnownApplications returns the list of known application definitions.
func GetKnownApplications() []AppDefinition {
	return knownApplications
}

// Redaction patterns for sensitive data
var (
	// Key name patterns (case-insensitive)
	sensitiveKeyPatterns = []string{
		`password`, `passwd`, `pwd`,
		`secret`, `private`,
		`token`, `apikey`, `api_key`, `api-key`,
		`credential`, `cred`,
		`auth`, `authentication`,
		`certificate`, `cert`,
		`connection_string`, `connectionstring`, `connstr`,
		`access_key`, `secret_key`, `private_key`,
	}

	// Value patterns (regex)
	sensitiveValuePatterns = []*regexp.Regexp{
		// Connection strings
		regexp.MustCompile(`(?i)(mongodb|mysql|postgres|postgresql|redis|amqp|mssql|oracle):\/\/[^\s"'\x60]+`),
		// AWS credentials
		regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
		// JWT tokens
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		// Bearer tokens
		regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_-]{20,}`),
		// PEM blocks
		regexp.MustCompile(`-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----`),
		// Azure account keys
		regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/=]{86,88}`),
		// Generic API keys (long alphanumeric strings)
		regexp.MustCompile(`[A-Za-z0-9]{32,}`),
		// Hex-encoded secrets (32+ chars)
		regexp.MustCompile(`[a-fA-F0-9]{32,}`),
	}

	// Environment variable patterns (flag but don't fully redact)
	envVarPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`),
		regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*`),
		regexp.MustCompile(`%[A-Za-z_][A-Za-z0-9_]*%`),
	}

	// Template patterns
	templatePatterns = []*regexp.Regexp{
		regexp.MustCompile(`\{\{[^}]+\}\}`),
	}
)

// redactedPlaceholder is the string used to replace sensitive values.
const redactedPlaceholder = "[REDACTED]"

// GetAppConfig reads and returns an application config file with sensitive data redacted.
func (c *Collector) GetAppConfig(path string) (*types.AppConfigResult, error) {
	result := &types.AppConfigResult{
		Path:      path,
		Timestamp: time.Now(),
		RedactionSummary: types.RedactionSummary{
			ByType: make(map[string]int),
		},
	}

	// Check if file exists and is readable
	info, err := os.Stat(path)
	if err != nil {
		result.Readable = false
		result.Error = err.Error()
		return result, nil
	}

	result.FileSize = info.Size()
	result.ModTime = info.ModTime()

	// Read file content
	content, err := os.ReadFile(path) // #nosec G304 -- intentionally reading user-specified config path
	if err != nil {
		result.Readable = false
		result.Error = err.Error()
		return result, nil
	}
	result.Readable = true

	// Detect format
	result.Format = detectConfigFormat(path, content)

	// Apply redaction
	redactedContent, summary := redactConfig(string(content), result.Format)
	result.Content = redactedContent
	result.RedactionSummary = summary

	// Extract keys/sections based on format
	result.ParsedKeys, result.Sections = extractKeysAndSections(redactedContent, result.Format)

	return result, nil
}

// detectConfigFormat determines the config file format.
func detectConfigFormat(path string, content []byte) string {
	ext := strings.ToLower(filepath.Ext(path))
	baseName := strings.ToLower(filepath.Base(path))

	// Check by extension first
	switch ext {
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".xml":
		return "xml"
	case ".ini", ".cfg":
		return "ini"
	case ".conf":
		// Could be nginx, apache, or general config
		if strings.Contains(baseName, "nginx") {
			return "nginx"
		}
		if strings.Contains(baseName, "apache") || strings.Contains(baseName, "httpd") {
			return "apache"
		}
		return "conf"
	case ".env":
		return "env"
	case ".properties":
		return "properties"
	}

	// Check by content
	contentStr := string(content)
	trimmed := strings.TrimSpace(contentStr)

	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "json"
	}
	if strings.HasPrefix(trimmed, "<?xml") || strings.HasPrefix(trimmed, "<") {
		return "xml"
	}
	if strings.Contains(contentStr, "server {") || strings.Contains(contentStr, "location ") {
		return "nginx"
	}
	if strings.Contains(contentStr, "<VirtualHost") || strings.Contains(contentStr, "DocumentRoot") {
		return "apache"
	}
	if strings.Contains(contentStr, "---") && (strings.Contains(contentStr, ": ") || strings.Contains(contentStr, ":\n")) {
		return "yaml"
	}

	// Check for INI-style sections
	if strings.Contains(contentStr, "[") && strings.Contains(contentStr, "]") {
		return "ini"
	}

	// Check for key=value format
	if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`).MatchString(trimmed) {
		return "env"
	}

	return "unknown"
}

// redactConfig applies redaction rules to config content.
func redactConfig(content, format string) (string, types.RedactionSummary) {
	summary := types.RedactionSummary{
		ByType:       make(map[string]int),
		RedactedKeys: []string{},
	}

	// Count environment variable references
	for _, pattern := range envVarPatterns {
		matches := pattern.FindAllString(content, -1)
		summary.EnvVarRefs += len(matches)
	}

	// Count template references
	for _, pattern := range templatePatterns {
		matches := pattern.FindAllString(content, -1)
		summary.TemplateRefs += len(matches)
	}

	// Process line by line for key-based redaction
	lines := strings.Split(content, "\n")
	var redactedLines []string

	for _, line := range lines {
		redactedLine := line
		lineRedacted := false

		// Check for sensitive keys in the line
		for _, keyPattern := range sensitiveKeyPatterns {
			keyRegex := regexp.MustCompile(`(?i)(["']?)` + keyPattern + `["']?\s*[=:]\s*(.+)`)
			if matches := keyRegex.FindStringSubmatch(line); len(matches) > 0 {
				// Get the value part and redact it
				valuePart := matches[2]
				// Don't redact if value is an env var reference
				if !isEnvVarReference(valuePart) {
					redactedLine = keyRegex.ReplaceAllString(line, `$1`+keyPattern+`$1: `+redactedPlaceholder)
					summary.ByType[keyPattern]++
					summary.TotalRedactions++
					summary.RedactedKeys = append(summary.RedactedKeys, keyPattern)
					lineRedacted = true
					break
				}
			}
		}

		// If no key-based redaction, check for value patterns
		if !lineRedacted {
			for _, pattern := range sensitiveValuePatterns {
				if pattern.MatchString(redactedLine) {
					// Don't redact if it's clearly a template or env var
					match := pattern.FindString(redactedLine)
					if !isEnvVarReference(match) && !isTemplateReference(match) {
						redactedLine = pattern.ReplaceAllString(redactedLine, redactedPlaceholder)
						summary.ByType["value_pattern"]++
						summary.TotalRedactions++
					}
				}
			}
		}

		redactedLines = append(redactedLines, redactedLine)
	}

	return strings.Join(redactedLines, "\n"), summary
}

// isEnvVarReference checks if a string is an environment variable reference.
func isEnvVarReference(s string) bool {
	s = strings.TrimSpace(s)
	for _, pattern := range envVarPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}
	return false
}

// isTemplateReference checks if a string is a template reference.
func isTemplateReference(s string) bool {
	for _, pattern := range templatePatterns {
		if pattern.MatchString(s) {
			return true
		}
	}
	return false
}

// extractKeysAndSections extracts top-level keys and sections from config content.
func extractKeysAndSections(content, format string) ([]string, []string) {
	var keys []string
	var sections []string
	seenKeys := make(map[string]bool)
	seenSections := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}

		switch format {
		case "ini", "conf":
			// Extract [section] headers
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section := strings.Trim(line, "[]")
				if !seenSections[section] {
					sections = append(sections, section)
					seenSections[section] = true
				}
			} else if idx := strings.Index(line, "="); idx > 0 {
				key := strings.TrimSpace(line[:idx])
				if !seenKeys[key] {
					keys = append(keys, key)
					seenKeys[key] = true
				}
			}
		case "env", "properties":
			if idx := strings.Index(line, "="); idx > 0 {
				key := strings.TrimSpace(line[:idx])
				if !seenKeys[key] {
					keys = append(keys, key)
					seenKeys[key] = true
				}
			}
		case "yaml":
			// Extract top-level keys (lines without leading whitespace that end with :)
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				key := strings.TrimSpace(parts[0])
				if key != "" && !strings.HasPrefix(key, "-") && !seenKeys[key] {
					keys = append(keys, key)
					seenKeys[key] = true
				}
			}
		case "nginx":
			// Extract nginx directive names and blocks
			if strings.HasSuffix(line, "{") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					section := strings.TrimSuffix(parts[0], "{")
					if !seenSections[section] {
						sections = append(sections, section)
						seenSections[section] = true
					}
				}
			} else if !strings.HasSuffix(line, "}") && !strings.HasSuffix(line, ";") {
				continue
			} else {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					directive := parts[0]
					if !seenKeys[directive] {
						keys = append(keys, directive)
						seenKeys[directive] = true
					}
				}
			}
		case "apache":
			// Extract Apache directives and <Section> blocks
			if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
				section := strings.Trim(line, "<>")
				parts := strings.Fields(section)
				if len(parts) > 0 && !strings.HasPrefix(parts[0], "/") {
					if !seenSections[parts[0]] {
						sections = append(sections, parts[0])
						seenSections[parts[0]] = true
					}
				}
			} else {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					directive := parts[0]
					if !seenKeys[directive] {
						keys = append(keys, directive)
						seenKeys[directive] = true
					}
				}
			}
		case "json":
			// Basic key extraction for JSON (top-level only)
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				key := strings.Trim(strings.TrimSpace(parts[0]), `"`)
				if key != "" && key != "{" && key != "}" && !seenKeys[key] {
					keys = append(keys, key)
					seenKeys[key] = true
				}
			}
		}
	}

	return keys, sections
}

// fileExists checks if a file or directory exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// findExistingPaths returns paths that actually exist from a list of potential paths.
func findExistingPaths(paths []string) []string {
	var existing []string
	for _, p := range paths {
		// Handle glob patterns
		if strings.Contains(p, "*") {
			matches, err := filepath.Glob(p)
			if err == nil {
				existing = append(existing, matches...)
			}
		} else if fileExists(p) {
			existing = append(existing, p)
		}
	}
	return existing
}
