// Package logging provides AWGSocks' leveled, rotating file logger.
//
// Security note: this logger is the only sink used by AWGSocks and by the
// embedded AmneziaWG device. Every message passes through Redact, which strips
// anything that looks like a WireGuard/AmneziaWG key material blob before the
// line reaches a file or a console. See redact.go.
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Level is a logging severity.
type Level int32

// Logging levels, ordered by increasing severity.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// ParseLevel converts a textual level ("debug", "info", "warn", "error") to a
// Level. Unknown values return an error.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "info", "":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("invalid log level %q (debug|info|warn|error)", s)
	}
}

// String renders the level as its uppercase name.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Options configures a Logger.
type Options struct {
	// Dir is the directory that receives awgsocks.log. Empty disables file
	// logging (console-only).
	Dir string
	// FileName is the active log file name. Defaults to "awgsocks.log".
	FileName string
	// Level is the minimum severity that is written.
	Level Level
	// MaxSizeBytes is the rotation threshold. Defaults to 8 MiB.
	MaxSizeBytes int64
	// MaxFiles is how many rotated files to retain (excluding the active one).
	// Defaults to 5.
	MaxFiles int
	// Console, when non-nil, additionally receives every emitted line. Used by
	// the foreground `run` mode and by the CLI.
	Console io.Writer
}

// Logger is a leveled, size-rotating logger that is safe for concurrent use.
type Logger struct {
	mu       sync.Mutex
	opts     Options
	file     *os.File
	size     int64
	console  io.Writer
	closed   bool
	maxSize  int64
	maxFiles int
}

// New creates a Logger. When opts.Dir is set the directory is created if it does
// not exist. A failure to open the log file is reported, but the returned Logger
// still works against the console so that startup diagnostics are never lost.
func New(opts Options) (*Logger, error) {
	if opts.FileName == "" {
		opts.FileName = "awgsocks.log"
	}
	if opts.MaxSizeBytes <= 0 {
		opts.MaxSizeBytes = 8 << 20
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 5
	}
	l := &Logger{
		opts:     opts,
		console:  opts.Console,
		maxSize:  opts.MaxSizeBytes,
		maxFiles: opts.MaxFiles,
	}
	if opts.Dir == "" {
		return l, nil
	}
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return l, fmt.Errorf("could not create the log directory: %w", err)
	}
	if err := l.openFile(); err != nil {
		return l, err
	}
	return l, nil
}

func (l *Logger) openFile() error {
	path := filepath.Join(l.opts.Dir, l.opts.FileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("could not open the log file: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("could not stat the log file: %w", err)
	}
	l.file = f
	l.size = st.Size()
	return nil
}

// SetLevel changes the minimum severity at runtime.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.opts.Level = level
	l.mu.Unlock()
}

// SetRotation changes the rotation limits at runtime, so that a configuration
// reload can apply log_max_size_mb and log_max_files without restarting the
// service and losing the open log file.
//
// A value of zero or less leaves that limit alone, matching New, where zero
// means "use the default" rather than "use no limit".
func (l *Logger) SetRotation(maxSizeBytes int64, maxFiles int) {
	l.mu.Lock()
	if maxSizeBytes > 0 {
		l.maxSize = maxSizeBytes
	}
	if maxFiles > 0 {
		l.maxFiles = maxFiles
	}
	l.mu.Unlock()
}

// Rotation reports the limits in force.
func (l *Logger) Rotation() (maxSizeBytes int64, maxFiles int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxSize, l.maxFiles
}

// Level reports the current minimum severity.
func (l *Logger) Level() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.opts.Level
}

// Debugf logs at DEBUG.
func (l *Logger) Debugf(format string, args ...any) { l.logf(LevelDebug, format, args...) }

// Infof logs at INFO.
func (l *Logger) Infof(format string, args ...any) { l.logf(LevelInfo, format, args...) }

// Warnf logs at WARN.
func (l *Logger) Warnf(format string, args ...any) { l.logf(LevelWarn, format, args...) }

// Errorf logs at ERROR.
func (l *Logger) Errorf(format string, args ...any) { l.logf(LevelError, format, args...) }

func (l *Logger) logf(level Level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || level < l.opts.Level {
		return
	}
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	// Every line passes the secret scan before it reaches a file or a console.
	msg = Redact(strings.TrimRight(msg, "\r\n"))
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("2006-01-02 15:04:05.000"), level, msg)

	if l.console != nil {
		io.WriteString(l.console, line)
	}
	if l.file == nil {
		return
	}
	if l.size+int64(len(line)) > l.maxSize {
		l.rotateLocked()
	}
	n, err := l.file.WriteString(line)
	if err == nil {
		l.size += int64(n)
	}
}

// rotateLocked renames the active file to awgsocks-<timestamp>.log and opens a
// fresh one. Callers must hold l.mu.
func (l *Logger) rotateLocked() {
	if l.file == nil {
		return
	}
	l.file.Close()
	l.file = nil

	base := strings.TrimSuffix(l.opts.FileName, filepath.Ext(l.opts.FileName))
	ext := filepath.Ext(l.opts.FileName)
	active := filepath.Join(l.opts.Dir, l.opts.FileName)
	rotated := filepath.Join(l.opts.Dir, fmt.Sprintf("%s-%s%s", base, time.Now().Format("20060102-150405"), ext))
	if err := os.Rename(active, rotated); err != nil {
		// If renaming fails, truncate and carry on: losing old lines beats
		// losing logging altogether.
		os.Remove(active)
	}
	l.pruneLocked(base, ext)
	if err := l.openFile(); err != nil && l.console != nil {
		io.WriteString(l.console, "could not reopen the log file: "+err.Error()+"\n")
	}
}

// pruneLocked deletes the oldest rotated files beyond MaxFiles.
func (l *Logger) pruneLocked(base, ext string) {
	entries, err := os.ReadDir(l.opts.Dir)
	if err != nil {
		return
	}
	var rotated []string
	prefix := base + "-"
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ext) {
			rotated = append(rotated, name)
		}
	}
	if len(rotated) <= l.maxFiles {
		return
	}
	sort.Strings(rotated) // the timestamp format sorts lexicographically
	for _, name := range rotated[:len(rotated)-l.maxFiles] {
		os.Remove(filepath.Join(l.opts.Dir, name))
	}
}

// Close flushes and closes the underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}
