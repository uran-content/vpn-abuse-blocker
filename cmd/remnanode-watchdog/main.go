package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type RemoteConfig struct {
	Patterns []Pattern `json:"patterns"`
}

type ExtractRule struct {
	Type  string `json:"type"` // "after" or "regex"
	After string `json:"after,omitempty"`
	Until string `json:"until,omitempty"`
	Regex string `json:"regex,omitempty"`
	Group int    `json:"group,omitempty"`
}

type Pattern struct {
	ID          string      `json:"id"`
	Enabled     bool        `json:"enabled"`
	MustContain []string    `json:"mustContain"`
	MatchRegex  string      `json:"matchRegex,omitempty"`
	Extract     ExtractRule `json:"extract"`

	Threshold       int `json:"threshold"`
	WindowSeconds   int `json:"windowSeconds"`
	CooldownSeconds int `json:"cooldownSeconds"`

	MaxTrackedUsers int  `json:"maxTrackedUsers,omitempty"`
	IncludeSample   bool `json:"includeSample,omitempty"`
}

type compiledConfig struct {
	Patterns []*compiledPattern
}

type compiledPattern struct {
	Pattern

	matchRe   *regexp.Regexp
	extractRe *regexp.Regexp

	states map[string]*userState

	lastCleanup int64
	ttlSeconds  int64
	windowSec   int64
	cooldownSec int64
	threshold   int
	maxUsers    int
}

type userState struct {
	times       []int64
	lastTrigger int64
	lastSeen    int64
}

type Alert struct {
	PatternID     string
	UserID        string
	Count         int
	WindowSeconds int
	ObservedAt    time.Time
	Sample        string
}

type WebhookPayload struct {
	Event         string `json:"event"`
	Node          string `json:"node"`
	PatternID     string `json:"patternId"`
	UserID        string `json:"userId"`
	Count         int    `json:"count"`
	WindowSeconds int    `json:"windowSeconds"`
	ObservedAt    string `json:"observedAt"`
	Sample        string `json:"sample,omitempty"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	patternsURL := strings.TrimSpace(os.Getenv("PATTERNS_URL"))
	webhookURL := strings.TrimSpace(os.Getenv("WEBHOOK_URL"))
	if patternsURL == "" {
		log.Fatalf("PATTERNS_URL is required")
	}
	if webhookURL == "" {
		log.Fatalf("WEBHOOK_URL is required")
	}

	patternsToken := strings.TrimSpace(os.Getenv("PATTERNS_TOKEN"))
	webhookToken := strings.TrimSpace(os.Getenv("WEBHOOK_TOKEN"))

	nodeName := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if nodeName == "" {
		if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
			nodeName = h
		} else {
			nodeName = "unknown-node"
		}
	}

	pollEvery := parseEnvDuration("PATTERNS_POLL", 60*time.Second)
	httpTimeout := parseEnvDuration("HTTP_TIMEOUT", 2*time.Second)

	maxQueue := parseEnvInt("ALERT_QUEUE", 128)
	if maxQueue < 1 {
		maxQueue = 1
	}

	containerName := strings.TrimSpace(os.Getenv("CONTAINER_NAME"))
	if containerName == "" {
		containerName = "remnanode"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	alertsCh := make(chan Alert, maxQueue)

	var cfgValue atomic.Value
	cfgValue.Store((*compiledConfig)(nil))

	go patternPoller(ctx, patternsURL, patternsToken, pollEvery, &cfgValue)
	go webhookWorker(ctx, webhookURL, webhookToken, nodeName, httpTimeout, alertsCh)

	// Выбор источника логов:
	// 1) LOG_FILE (рекомендуется) — читаем tail -F с примонтированного файла
	// 2) LOG_CMD — кастомная команда
	// 3) по умолчанию — docker exec в remnanode и tail -F внутри контейнера
	cmdArgs := buildLogCommand(containerName)

	followLogs(ctx, cmdArgs, func(line string) {
		handleLine(&cfgValue, alertsCh, line)
	})
}

func buildLogCommand(containerName string) []string {
	if logFile := strings.TrimSpace(os.Getenv("LOG_FILE")); logFile != "" {
		// tail -n 0 => не проигрывать историю
		// -F => переживает ротацию/пересоздание файла
		return []string{"tail", "-n", "0", "-F", logFile}
	}

	if logCmd := strings.TrimSpace(os.Getenv("LOG_CMD")); logCmd != "" {
		a, err := splitCommand(logCmd)
		if err != nil {
			log.Fatalf("bad LOG_CMD: %v", err)
		}
		return a
	}

	// Default: docker exec … tail -F /var/log/supervisor/xray.out.log
	return []string{
		"docker", "exec", "-i", containerName,
		"sh", "-c", "tail -n 0 -F /var/log/supervisor/xray.out.log",
	}
}

func handleLine(cfgValue *atomic.Value, alertsCh chan<- Alert, line string) {
	v := cfgValue.Load()
	cfg, _ := v.(*compiledConfig)
	if cfg == nil || len(cfg.Patterns) == 0 {
		return
	}

	now := time.Now().Unix()

	for _, p := range cfg.Patterns {
		if p == nil || !p.Enabled {
			continue
		}
		if !containsAll(line, p.MustContain) {
			continue
		}
		if p.matchRe != nil && !p.matchRe.MatchString(line) {
			continue
		}

		userID, ok := extractUserID(p, line)
		if !ok {
			continue
		}

		if alert := p.observe(userID, now, line); alert != nil {
			select {
			case alertsCh <- *alert:
			default:
				// Дропаем при перегрузке — защита CPU/RAM
			}
		}
	}
}

func patternPoller(ctx context.Context, url, token string, every time.Duration, cfgValue *atomic.Value) {
	client := &http.Client{Timeout: 5 * time.Second}
	var etag string

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		if err := fetchAndCompile(ctx, client, url, token, &etag, cfgValue); err != nil {
			log.Printf("patternPoller: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func fetchAndCompile(ctx context.Context, client *http.Client, url, token string, etag *string, cfgValue *atomic.Value) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if etag != nil && *etag != "" {
		req.Header.Set("If-None-Match", *etag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return fmt.Errorf("patterns fetch failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if etag != nil {
		if v := resp.Header.Get("ETag"); strings.TrimSpace(v) != "" {
			*etag = v
		}
	}

	var rc RemoteConfig
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rc); err != nil {
		return fmt.Errorf("decode patterns: %w", err)
	}

	compiled, err := compileConfig(rc)
	if err != nil {
		return err
	}

	cfgValue.Store(compiled)
	log.Printf("loaded %d pattern(s)", len(compiled.Patterns))
	return nil
}

func compileConfig(rc RemoteConfig) (*compiledConfig, error) {
	out := &compiledConfig{Patterns: make([]*compiledPattern, 0, len(rc.Patterns))}

	for _, p := range rc.Patterns {
		if strings.TrimSpace(p.ID) == "" {
			continue
		}
		if p.Threshold <= 0 {
			p.Threshold = 1
		}
		if p.WindowSeconds <= 0 {
			p.WindowSeconds = 60
		}
		if p.CooldownSeconds < 0 {
			p.CooldownSeconds = 0
		}

		cp := &compiledPattern{
			Pattern:     p,
			states:      make(map[string]*userState, 1024),
			windowSec:   int64(p.WindowSeconds),
			cooldownSec: int64(p.CooldownSeconds),
			threshold:   p.Threshold,
		}

		if p.MaxTrackedUsers > 0 {
			cp.maxUsers = p.MaxTrackedUsers
		} else {
			cp.maxUsers = 20000
		}

		cp.ttlSeconds = cp.windowSec + cp.cooldownSec + 120
		if cp.ttlSeconds < 180 {
			cp.ttlSeconds = 180
		}

		if strings.TrimSpace(p.MatchRegex) != "" {
			re, err := regexp.Compile(p.MatchRegex)
			if err != nil {
				log.Printf("pattern %q: bad matchRegex: %v", p.ID, err)
				continue
			}
			cp.matchRe = re
		}

		switch strings.ToLower(strings.TrimSpace(p.Extract.Type)) {
		case "after":
			if strings.TrimSpace(p.Extract.After) == "" {
				log.Printf("pattern %q: extract.after is empty", p.ID)
				continue
			}
		case "regex":
			if strings.TrimSpace(p.Extract.Regex) == "" || p.Extract.Group <= 0 {
				log.Printf("pattern %q: extract.regex/group invalid", p.ID)
				continue
			}
			re, err := regexp.Compile(p.Extract.Regex)
			if err != nil {
				log.Printf("pattern %q: bad extract.regex: %v", p.ID, err)
				continue
			}
			cp.extractRe = re
		default:
			log.Printf("pattern %q: extract.type must be 'after' or 'regex'", p.ID)
			continue
		}

		out.Patterns = append(out.Patterns, cp)
	}

	return out, nil
}

func containsAll(s string, needles []string) bool {
	for _, n := range needles {
		if n == "" {
			continue
		}
		if !strings.Contains(s, n) {
			return false
		}
	}
	return true
}

func extractUserID(p *compiledPattern, line string) (string, bool) {
	r := p.Extract
	switch strings.ToLower(strings.TrimSpace(r.Type)) {
	case "after":
		idx := strings.Index(line, r.After)
		if idx < 0 {
			return "", false
		}
		start := idx + len(r.After)
		for start < len(line) {
			c := line[start]
			if c != ' ' && c != '\t' {
				break
			}
			start++
		}
		if start >= len(line) {
			return "", false
		}

		end := len(line)
		if strings.TrimSpace(r.Until) != "" {
			if j := strings.Index(line[start:], r.Until); j >= 0 {
				end = start + j
			}
		} else {
			for i := start; i < len(line); i++ {
				c := line[i]
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
					end = i
					break
				}
			}
		}

		v := strings.TrimSpace(line[start:end])
		return v, v != ""

	case "regex":
		if p.extractRe == nil {
			return "", false
		}
		m := p.extractRe.FindStringSubmatch(line)
		if m == nil {
			return "", false
		}
		g := r.Group
		if g <= 0 || g >= len(m) {
			return "", false
		}
		v := strings.TrimSpace(m[g])
		return v, v != ""

	default:
		return "", false
	}
}

func (p *compiledPattern) observe(userID string, now int64, line string) *Alert {
	if userID == "" {
		return nil
	}

	if p.lastCleanup == 0 {
		p.lastCleanup = now
	} else if now-p.lastCleanup >= 60 {
		p.cleanup(now)
		p.lastCleanup = now
	}

	st := p.states[userID]
	if st == nil {
		if p.maxUsers > 0 && len(p.states) >= p.maxUsers {
			return nil
		}
		st = &userState{times: make([]int64, 0, p.threshold)}
		p.states[userID] = st
	}

	st.lastSeen = now

	st.times = append(st.times, now)
	if len(st.times) > p.threshold {
		st.times = st.times[len(st.times)-p.threshold:]
	}

	if len(st.times) == p.threshold {
		if now-st.times[0] <= p.windowSec {
			if p.cooldownSec == 0 || now-st.lastTrigger >= p.cooldownSec {
				st.lastTrigger = now
				alert := &Alert{
					PatternID:     p.ID,
					UserID:        userID,
					Count:         p.threshold,
					WindowSeconds: int(p.windowSec),
					ObservedAt:    time.Unix(now, 0).UTC(),
				}
				if p.IncludeSample {
					alert.Sample = line
				}
				return alert
			}
		}
	}

	return nil
}

func (p *compiledPattern) cleanup(now int64) {
	if len(p.states) == 0 {
		return
	}

	ttl := p.ttlSeconds
	for k, st := range p.states {
		if st == nil {
			delete(p.states, k)
			continue
		}
		if now-st.lastSeen > ttl {
			delete(p.states, k)
		}
	}

	if p.maxUsers > 0 && len(p.states) > p.maxUsers {
		overflow := len(p.states) - p.maxUsers
		for k := range p.states {
			delete(p.states, k)
			overflow--
			if overflow <= 0 {
				break
			}
		}
	}
}

func webhookWorker(ctx context.Context, url, token, node string, timeout time.Duration, alerts <-chan Alert) {
	client := &http.Client{Timeout: timeout}

	for {
		select {
		case <-ctx.Done():
			return
		case a := <-alerts:
			payload := WebhookPayload{
				Event:         "pattern_match",
				Node:          node,
				PatternID:     a.PatternID,
				UserID:        a.UserID,
				Count:         a.Count,
				WindowSeconds: a.WindowSeconds,
				ObservedAt:    a.ObservedAt.Format(time.RFC3339Nano),
			}
			if a.Sample != "" {
				payload.Sample = a.Sample
			}

			body, _ := json.Marshal(payload)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
			resp.Body.Close()
		}
	}
}

func followLogs(ctx context.Context, cmdArgs []string, onLine func(string)) {
	if len(cmdArgs) == 0 {
		log.Fatalf("empty log command")
	}

	backoff := 1 * time.Second

	for {
		if ctx.Err() != nil {
			return
		}

		err := runCommandStream(ctx, cmdArgs, onLine)
		if ctx.Err() != nil {
			return
		}

		if err != nil {
			log.Printf("log stream ended: %v", err)
		} else {
			log.Printf("log stream ended")
		}

		time.Sleep(backoff)
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func runCommandStream(ctx context.Context, cmdArgs []string, onLine func(string)) error {
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() { _, _ = io.Copy(os.Stderr, stderr) }()

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			onLine(line)
		}
		if ctx.Err() != nil {
			break
		}
	}

	scanErr := scanner.Err()
	waitErr := cmd.Wait()

	if scanErr != nil {
		return scanErr
	}
	if waitErr != nil {
		return waitErr
	}
	return nil
}

func parseEnvDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func parseEnvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func splitCommand(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}

	var out []string
	var cur strings.Builder

	inSingle := false
	inDouble := false
	esc := false

	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]

		if esc {
			cur.WriteByte(c)
			esc = false
			continue
		}
		if c == '\\' && inDouble {
			esc = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble {
			if c == ' ' || c == '\t' || c == '\n' {
				flush()
				continue
			}
		}
		cur.WriteByte(c)
	}

	if inSingle || inDouble || esc {
		return nil, errors.New("unclosed quote or escape")
	}
	flush()
	if len(out) == 0 {
		return nil, errors.New("empty")
	}
	return out, nil
}
