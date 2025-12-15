package audit

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultProvider implements audit logging to local files in JSON Lines format.
//
// Features:
//   - JSON Lines format (one JSON object per line)
//   - Tamper-evident with SHA-256 hash chain
//   - Append-only writes (O_APPEND flag)
//   - Async buffered writing with configurable flush
//   - File rotation by size
//   - Optional gzip compression for rotated files
//   - Fsync support for durability
type DefaultProvider struct {
	config Config

	// File handling
	file     *os.File
	writer   *bufio.Writer
	filePath string
	fileSize int64
	fileMu   sync.Mutex

	// Buffering
	buffer   chan *Event
	bufferWg sync.WaitGroup

	// Hash chain
	lastHash   string
	lastHashMu sync.Mutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	closed bool
}

func init() {
	RegisterProvider("default", NewDefaultProvider)
}

// NewDefaultProvider creates a new file-based audit provider.
func NewDefaultProvider(cfg Config) (Provider, error) {
	if cfg.Output == "" {
		return nil, &AuditError{Message: "output path is required"}
	}

	// Ensure directory exists
	dir := filepath.Dir(cfg.Output)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, &AuditError{Message: "failed to create audit directory", Cause: err}
	}

	// Open file in append-only mode
	// O_APPEND ensures atomic appends even with concurrent writers
	// O_CREATE creates if not exists
	// O_WRONLY for write-only (no reading, enhances security)
	// #nosec G302 -- 0640 is intentional: group-readable for log forwarding (e.g., adm group)
	file, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, &AuditError{Message: "failed to open audit file", Cause: err}
	}

	// Get current file size
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, &AuditError{Message: "failed to stat audit file", Cause: err}
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &DefaultProvider{
		config:   cfg,
		file:     file,
		writer:   bufio.NewWriterSize(file, 64*1024), // 64KB buffer
		filePath: cfg.Output,
		fileSize: info.Size(),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Initialize hash chain from existing file if needed
	if cfg.IncludeHash {
		if err := p.initHashChain(); err != nil {
			_ = file.Close()
			return nil, err
		}
	}

	// Start async writer if buffering enabled
	if cfg.BufferSize > 0 {
		p.buffer = make(chan *Event, cfg.BufferSize)
		p.bufferWg.Add(1)
		go p.asyncWriter()
	}

	return p, nil
}

// Name returns the provider identifier.
func (p *DefaultProvider) Name() string {
	return "default"
}

// Write writes an event to the audit log.
func (p *DefaultProvider) Write(ctx context.Context, event *Event) error {
	if p.closed {
		return &AuditError{Message: "provider is closed"}
	}

	// Populate event fields
	p.populateEvent(event)

	// If buffering, send to async writer
	if p.buffer != nil {
		select {
		case p.buffer <- event:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-p.ctx.Done():
			return &AuditError{Message: "provider is shutting down"}
		}
	}

	// Synchronous write
	return p.writeEvent(event)
}

// Flush ensures all buffered events are written.
func (p *DefaultProvider) Flush(ctx context.Context) error {
	p.fileMu.Lock()
	defer p.fileMu.Unlock()

	if err := p.writer.Flush(); err != nil {
		return &AuditError{Message: "failed to flush buffer", Cause: err}
	}

	if p.config.SyncWrite {
		if err := p.file.Sync(); err != nil {
			return &AuditError{Message: "failed to sync file", Cause: err}
		}
	}

	return nil
}

// Close closes the provider and releases resources.
func (p *DefaultProvider) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true

	// Signal async writer to stop
	p.cancel()

	// Close buffer channel and wait for async writer
	if p.buffer != nil {
		close(p.buffer)
		p.bufferWg.Wait()
	}

	p.fileMu.Lock()
	defer p.fileMu.Unlock()

	// Final flush
	if err := p.writer.Flush(); err != nil {
		return &AuditError{Message: "failed to flush on close", Cause: err}
	}

	// Sync to disk
	if err := p.file.Sync(); err != nil {
		return &AuditError{Message: "failed to sync on close", Cause: err}
	}

	return p.file.Close()
}

// Verify checks the integrity of the audit log by validating the hash chain.
func (p *DefaultProvider) Verify(ctx context.Context) (int, error) {
	// Open file for reading
	// #nosec G304 -- path is from trusted config
	file, err := os.Open(p.filePath)
	if err != nil {
		return 0, &AuditError{Message: "failed to open audit file for verification", Cause: err}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer for potentially long lines
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	var count int
	var prevHash string

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return count, ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			return count, &AuditError{
				Message: fmt.Sprintf("failed to parse event at line %d", count+1),
				Cause:   err,
			}
		}

		// Verify hash chain
		if p.config.IncludeHash {
			if event.PreviousHash != prevHash {
				return count, &AuditError{
					Message: fmt.Sprintf("hash chain broken at event %d (seq=%d)", count+1, event.Sequence),
				}
			}

			// Compute expected hash
			expectedHash := p.computeHash(&event)
			if event.Hash != expectedHash {
				return count, &AuditError{
					Message: fmt.Sprintf("hash mismatch at event %d (seq=%d)", count+1, event.Sequence),
				}
			}

			prevHash = event.Hash
		}

		count++
	}

	if err := scanner.Err(); err != nil {
		return count, &AuditError{Message: "error reading audit file", Cause: err}
	}

	return count, nil
}

// populateEvent fills in automatic fields.
func (p *DefaultProvider) populateEvent(event *Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}

	event.Sequence = nextSequence()

	// Compute hash chain
	if p.config.IncludeHash {
		p.lastHashMu.Lock()
		event.PreviousHash = p.lastHash
		event.Hash = p.computeHash(event)
		p.lastHash = event.Hash
		p.lastHashMu.Unlock()
	}
}

// computeHash computes the SHA-256 hash of an event.
// The hash is computed over all fields except the Hash field itself.
func (p *DefaultProvider) computeHash(event *Event) string {
	// Create a copy without the hash field
	hashInput := struct {
		Timestamp     time.Time              `json:"timestamp"`
		Sequence      uint64                 `json:"seq"`
		EventID       string                 `json:"event_id"`
		CorrelationID string                 `json:"correlation_id,omitempty"`
		Action        string                 `json:"action"`
		Resource      string                 `json:"resource,omitempty"`
		Identity      string                 `json:"identity,omitempty"`
		ClientIP      string                 `json:"client_ip,omitempty"`
		Parameters    map[string]interface{} `json:"params,omitempty"`
		Result        EventResult            `json:"result"`
		Error         string                 `json:"error,omitempty"`
		Duration      time.Duration          `json:"duration_ns,omitempty"`
		Metadata      map[string]interface{} `json:"metadata,omitempty"`
		PreviousHash  string                 `json:"prev_hash,omitempty"`
	}{
		Timestamp:     event.Timestamp,
		Sequence:      event.Sequence,
		EventID:       event.EventID,
		CorrelationID: event.CorrelationID,
		Action:        event.Action,
		Resource:      event.Resource,
		Identity:      event.Identity,
		ClientIP:      event.ClientIP,
		Parameters:    event.Parameters,
		Result:        event.Result,
		Error:         event.Error,
		Duration:      event.Duration,
		Metadata:      event.Metadata,
		PreviousHash:  event.PreviousHash,
	}

	data, _ := json.Marshal(hashInput)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// writeEvent writes a single event to the file.
func (p *DefaultProvider) writeEvent(event *Event) error {
	p.fileMu.Lock()
	defer p.fileMu.Unlock()

	// Check if rotation needed
	if p.config.MaxFileSize > 0 && p.fileSize >= p.config.MaxFileSize {
		if err := p.rotate(); err != nil {
			return err
		}
	}

	// Marshal event
	data, err := json.Marshal(event)
	if err != nil {
		return &AuditError{Message: "failed to marshal event", Cause: err}
	}

	// Write with newline
	data = append(data, '\n')

	n, err := p.writer.Write(data)
	if err != nil {
		return &AuditError{Message: "failed to write event", Cause: err}
	}
	p.fileSize += int64(n)

	// Sync if configured
	if p.config.SyncWrite {
		if err := p.writer.Flush(); err != nil {
			return &AuditError{Message: "failed to flush", Cause: err}
		}
		if err := p.file.Sync(); err != nil {
			return &AuditError{Message: "failed to sync", Cause: err}
		}
	}

	return nil
}

// asyncWriter processes events from the buffer.
func (p *DefaultProvider) asyncWriter() {
	defer p.bufferWg.Done()

	ticker := time.NewTicker(p.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-p.buffer:
			if !ok {
				// Channel closed, drain remaining
				return
			}
			if err := p.writeEvent(event); err != nil {
				// Log error but continue (audit shouldn't crash the app)
				_ = err
			}

		case <-ticker.C:
			_ = p.Flush(p.ctx)

		case <-p.ctx.Done():
			// Drain buffer before exit
			for event := range p.buffer {
				_ = p.writeEvent(event)
			}
			return
		}
	}
}

// rotate rotates the current log file.
func (p *DefaultProvider) rotate() error {
	// Flush current buffer
	if err := p.writer.Flush(); err != nil {
		return &AuditError{Message: "failed to flush before rotation", Cause: err}
	}

	// Sync to disk
	if err := p.file.Sync(); err != nil {
		return &AuditError{Message: "failed to sync before rotation", Cause: err}
	}

	// Close current file
	if err := p.file.Close(); err != nil {
		return &AuditError{Message: "failed to close file for rotation", Cause: err}
	}

	// Generate rotated filename with timestamp
	timestamp := time.Now().UTC().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", p.filePath, timestamp)

	// Rename current file
	if err := os.Rename(p.filePath, rotatedPath); err != nil {
		return &AuditError{Message: "failed to rename file during rotation", Cause: err}
	}

	// Compress rotated file in background
	go p.compressRotated(rotatedPath)

	// Clean up old rotated files
	go p.cleanupRotated()

	// Open new file
	// #nosec G302 -- 0640 is intentional: group-readable for log forwarding
	file, err := os.OpenFile(p.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return &AuditError{Message: "failed to open new file after rotation", Cause: err}
	}

	p.file = file
	p.writer = bufio.NewWriterSize(file, 64*1024)
	p.fileSize = 0

	return nil
}

// compressRotated compresses a rotated log file.
func (p *DefaultProvider) compressRotated(path string) {
	// #nosec G304 -- path is from trusted rotation logic
	src, err := os.Open(path)
	if err != nil {
		return
	}
	defer src.Close()

	// #nosec G304 -- path is constructed from trusted source
	dst, err := os.Create(path + ".gz")
	if err != nil {
		return
	}
	defer dst.Close()

	gz := gzip.NewWriter(dst)
	gz.Name = filepath.Base(path)
	gz.ModTime = time.Now()

	if _, err := io.Copy(gz, src); err != nil {
		_ = gz.Close()
		_ = os.Remove(path + ".gz")
		return
	}

	if err := gz.Close(); err != nil {
		_ = os.Remove(path + ".gz")
		return
	}

	// Remove uncompressed file
	_ = os.Remove(path)
}

// cleanupRotated removes old rotated files beyond MaxFiles.
func (p *DefaultProvider) cleanupRotated() {
	if p.config.MaxFiles <= 0 {
		return
	}

	dir := filepath.Dir(p.filePath)
	base := filepath.Base(p.filePath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	// Find rotated files
	var rotated []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, base+".") && (strings.HasSuffix(name, ".gz") || !strings.Contains(name[len(base)+1:], ".")) {
			rotated = append(rotated, filepath.Join(dir, name))
		}
	}

	// Sort by name (timestamp-based, so chronological)
	sort.Strings(rotated)

	// Remove oldest files beyond limit
	if len(rotated) > p.config.MaxFiles {
		for _, path := range rotated[:len(rotated)-p.config.MaxFiles] {
			_ = os.Remove(path)
		}
	}
}

// initHashChain reads the last event from the file to initialize the hash chain.
func (p *DefaultProvider) initHashChain() error {
	if p.fileSize == 0 {
		return nil
	}

	// Read the last line of the file
	// #nosec G304 -- path is from trusted config
	file, err := os.Open(p.filePath)
	if err != nil {
		return &AuditError{Message: "failed to open file for hash chain init", Cause: err}
	}
	defer file.Close()

	// Seek to near end of file
	seekPos := p.fileSize - 4096
	if seekPos < 0 {
		seekPos = 0
	}
	if _, err := file.Seek(seekPos, io.SeekStart); err != nil {
		return &AuditError{Message: "failed to seek for hash chain init", Cause: err}
	}

	// Read and find last complete line
	scanner := bufio.NewScanner(file)
	var lastLine string
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lastLine = line
		}
	}

	if lastLine == "" {
		return nil
	}

	// Parse last event to get its hash
	var event Event
	if err := json.Unmarshal([]byte(lastLine), &event); err != nil {
		return &AuditError{Message: "failed to parse last event for hash chain", Cause: err}
	}

	// Also restore sequence number
	sequenceMu.Lock()
	if event.Sequence >= sequence {
		sequence = event.Sequence
	}
	sequenceMu.Unlock()

	p.lastHash = event.Hash
	return nil
}
