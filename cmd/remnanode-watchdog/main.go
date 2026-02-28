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
	"net"
	"sync"
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

	ServerPolicy     string   `json:"serverPolicy,omitempty"`      // DEFAULT_APPLY | DEFAULT_SKIP
	ServerExceptions []string `json:"serverExceptions,omitempty"`  // IPv4 списка исключений

	BanType string `json:"banType,omitempty"` // WEBHOOK | FIRST_IP_WEBHOOK_AFTER
	UserIdType string `json:"userIdType,omitempty"` // EMAIL | IP
}

const (
	ServerPolicyDefaultApply = "DEFAULT_APPLY"
	ServerPolicyDefaultSkip  = "DEFAULT_SKIP"

	BanTypeWebhook              = "WEBHOOK"
	BanTypeFirstIPWebhookAfter  = "FIRST_IP_WEBHOOK_AFTER"
)

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
	times []int64
	ips   []string

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
	BanType  string
	BannedIP string
	UserIdType string
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

	BanType       string `json:"banType,omitempty"`
	UserIdType string `json:"userIdType,omitempty"` // EMAIL | IP
	BannedIP      string `json:"bannedIp,omitempty"`
	FirewallType  string `json:"firewallType,omitempty"`
	FirewallOk    *bool  `json:"firewallOk,omitempty"`
	FirewallError string `json:"firewallError,omitempty"`
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

	nodeIP := discoverPublicIPv4()
	nodeName := nodeIP
	if nodeName == "" {
		// fallback чтобы сервис не падал, если IP не получилось определить
		if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
			nodeName = h
		} else {
			nodeName = "unknown-node"
		}
	}

	pollEvery := parseEnvDuration("PATTERNS_POLL", 60*time.Second)
	httpTimeout := parseEnvDuration("HTTP_TIMEOUT", 2*time.Second)

	nftCmd := strings.TrimSpace(os.Getenv("NFT_BAN_CMD"))
	if nftCmd == "" {
		nftCmd = "nft add element inet remnaguard blocked_ipv4 { %IP% }"
	}
	nftTimeout := parseEnvDuration("NFT_BAN_TIMEOUT", 800*time.Millisecond)
	nftDedup := parseEnvDuration("NFT_BAN_DEDUP_TTL", 3600*time.Second)
	banner := NewFirewallBanner(nftCmd, nftTimeout, nftDedup)

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

	if banner != nil {
		if ok, errText := banner.EnsureNftables(ctx); !ok {
			log.Printf("nft ensure failed: %s", errText)
		} else {
			log.Printf("nft ensure ok")
		}
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	alertsCh := make(chan Alert, maxQueue)

	var cfgValue atomic.Value
	cfgValue.Store((*compiledConfig)(nil))

	go patternPoller(ctx, patternsURL, patternsToken, pollEvery, nodeIP, &cfgValue)
	go webhookWorker(ctx, webhookURL, webhookToken, nodeName, httpTimeout, banner, alertsCh)

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

		srcIP := ""
		needIP := (strings.ToUpper(strings.TrimSpace(p.UserIdType)) == "IP") ||
				(strings.ToUpper(strings.TrimSpace(p.BanType)) == BanTypeFirstIPWebhookAfter)

		if needIP {
			if ip, ok := extractSourceIPv4(line); ok {
				srcIP = ip
			}
		}

		var userID string
		if strings.ToUpper(strings.TrimSpace(p.UserIdType)) == "IP" {
			if srcIP == "" {
				// без IP нельзя определить уникальность — пропускаем
				continue
			}
			userID = srcIP
		} else {
			uid, ok := extractUserID(p, line)
			if !ok {
				continue
			}
			userID = uid
		}

		if alert := p.observe(userID, now, srcIP, line); alert != nil {
			select {
			case alertsCh <- *alert:
			default:
				// Дропаем при перегрузке — защита CPU/RAM
			}
		}
	}
}

func patternPoller(ctx context.Context, url, token string, every time.Duration, nodeIP string, cfgValue *atomic.Value) {
	client := &http.Client{Timeout: 5 * time.Second}
	var etag string

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		if err := fetchAndCompile(ctx, client, url, token, nodeIP, &etag, cfgValue); err != nil {
			log.Printf("patternPoller: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func fetchAndCompile(ctx context.Context, client *http.Client, url, token string, nodeIP string, etag *string, cfgValue *atomic.Value) error {
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

	compiled, err := compileConfig(rc, nodeIP)
	if err != nil {
		return err
	}

	cfgValue.Store(compiled)
	log.Printf("loaded %d pattern(s)", len(compiled.Patterns))
	return nil
}

func compileConfig(rc RemoteConfig, serverIPv4 string) (*compiledConfig, error) {
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
		if strings.TrimSpace(p.ServerPolicy) == "" {
			p.ServerPolicy = ServerPolicyDefaultApply
		}
		if !patternAppliesToThisServer(p, serverIPv4) {
			continue
		}
		bt := strings.ToUpper(strings.TrimSpace(p.BanType))
		if bt == "" {
			bt = BanTypeWebhook
		}
		if bt != BanTypeWebhook && bt != BanTypeFirstIPWebhookAfter {
			bt = BanTypeWebhook
		}
		p.BanType = bt
		uit := strings.ToUpper(strings.TrimSpace(p.UserIdType))
		if uit == "" {
			uit = "EMAIL"
		}
		if uit != "EMAIL" && uit != "IP" {
			uit = "EMAIL"
		}
		p.UserIdType = uit

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

		if p.UserIdType != "IP" {
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
		} else {

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

func (p *compiledPattern) observe(userID string, now int64, srcIP string, line string) *Alert {
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
		if p.BanType == BanTypeFirstIPWebhookAfter {
			st.ips = make([]string, 0, p.threshold)
		}
		p.states[userID] = st
	}

	st.lastSeen = now

	st.times = append(st.times, now)
	if p.BanType == BanTypeFirstIPWebhookAfter {
		st.ips = append(st.ips, srcIP)
	}
	if len(st.times) > p.threshold {
		st.times = st.times[len(st.times)-p.threshold:]
		if p.BanType == BanTypeFirstIPWebhookAfter && len(st.ips) > p.threshold {
			st.ips = st.ips[len(st.ips)-p.threshold:]
		}
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
					UserIdType:    p.UserIdType,
				}
				alert.BanType = p.BanType
				if p.BanType == BanTypeFirstIPWebhookAfter {
					if len(st.ips) == p.threshold && st.ips[0] != "" {
						alert.BannedIP = st.ips[0]
					} else {
						alert.BannedIP = srcIP
					}
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

func webhookWorker(ctx context.Context, url, token, node string, timeout time.Duration, banner *FirewallBanner, alerts <-chan Alert) {
	client := &http.Client{Timeout: timeout}

	for {
		select {
		case <-ctx.Done():
			return
		case a := <-alerts:
			var banType string
			var bannedIP string
			var fwType string
			var fwOkPtr *bool
			var fwErr string

			if a.BanType == BanTypeFirstIPWebhookAfter {
				banType = a.BanType
				bannedIP = a.BannedIP
				fwType = "nftables"

				ok, errText := false, "banner not configured"
				if banner != nil && bannedIP != "" {
					ok, errText = banner.BanIPv4(ctx, bannedIP)
				}
				fwOkPtr = &ok
				if errText != "" {
					fwErr = errText
				}
			}

			payload := WebhookPayload{
				Event:         "pattern_match",
				Node:          node,
				PatternID:     a.PatternID,
				UserID:        a.UserID,
				Count:         a.Count,
				WindowSeconds: a.WindowSeconds,
				ObservedAt:    a.ObservedAt.Format(time.RFC3339Nano),
				UserIdType:    a.UserIdType,
			}
			if banType != "" {
				payload.BanType = banType
				payload.BannedIP = bannedIP
				payload.FirewallType = fwType
				payload.FirewallOk = fwOkPtr
				payload.FirewallError = fwErr
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

func patternAppliesToThisServer(p Pattern, serverIPv4 string) bool {
	if serverIPv4 == "" {
		// если не смогли определить IP — не ломаем поведение
		return true
	}

	policy := strings.ToUpper(strings.TrimSpace(p.ServerPolicy))
	if policy == "" {
		policy = ServerPolicyDefaultApply
	}

	inExceptions := false
	for _, s := range p.ServerExceptions {
		if strings.TrimSpace(s) == serverIPv4 {
			inExceptions = true
			break
		}
	}

	switch policy {
	case ServerPolicyDefaultApply:
		// применяем везде, кроме исключений
		return !inExceptions
	case ServerPolicyDefaultSkip:
		// пропускаем везде, кроме исключений
		return inExceptions
	default:
		// безопасный дефолт как DEFAULT_APPLY
		return !inExceptions
	}
}

func extractSourceIPv4(line string) (string, bool) {
	// ищем " from "
	idx := strings.Index(line, " from ")
	if idx < 0 {
		if strings.HasPrefix(line, "from ") {
			idx = 0
		} else {
			idx = strings.Index(line, "from ")
			if idx < 0 {
				return "", false
			}
		}
	}

	// start после " from " или "from "
	start := idx
	if strings.HasPrefix(line[start:], " from ") {
		start += len(" from ")
	} else if strings.HasPrefix(line[start:], "from ") {
		start += len("from ")
	} else {
		// если попали на "from " без пробела до
		start += len("from ")
	}

	// токен до пробела
	end := start
	for end < len(line) {
		c := line[end]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			break
		}
		end++
	}
	if end <= start {
		return "", false
	}

	token := line[start:end] // например "tcp:195.209.160.197:15955" или "188.128.77.62:2416"

	// убираем префикс tcp:/udp:
	if strings.HasPrefix(token, "tcp:") {
		token = token[len("tcp:"):]
	} else if strings.HasPrefix(token, "udp:") {
		token = token[len("udp:"):]
	}

	// берём часть до первого ":" => IPv4
	if i := strings.IndexByte(token, ':'); i > 0 {
		token = token[:i]
	}

	ip := net.ParseIP(strings.TrimSpace(token))
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	// банить приватные смысла нет — защитимся
	if isPrivateIPv4(ip.To4()) {
		return "", false
	}
	return ip.To4().String(), true
}

// discoverPublicIPv4 tries to find the public IPv4 once at startup.
// 1) NODE_IP_OVERRIDE (optional)
// 2) outbound IPv4 via udp4 dial (usually equals public IPv4 on VPS)
// 3) fallback to external services (one request) if outbound is private/empty
func discoverPublicIPv4() string {
	// Optional override (for exotic setups)
	if v := strings.TrimSpace(os.Getenv("NODE_IP_OVERRIDE")); v != "" {
		if ip := net.ParseIP(v); ip != nil && ip.To4() != nil {
			return ip.To4().String()
		}
	}

	out := outboundIPv4()
	if out != "" {
		ip := net.ParseIP(out)
		if ip != nil && ip.To4() != nil && !isPrivateIPv4(ip.To4()) {
			return ip.To4().String()
		}
	}

	// One-time external fallback
	if ip := fetchPublicIPv4FromHTTP(); ip != "" {
		return ip
	}

	// Last resort: return whatever outbound is (may be private)
	return out
}

func outboundIPv4() string {
	conn, err := net.Dial("udp4", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || la.IP == nil {
		return ""
	}
	ip := la.IP.To4()
	if ip == nil {
		return ""
	}
	return ip.String()
}

func fetchPublicIPv4FromHTTP() string {
	client := &http.Client{Timeout: 2 * time.Second}
	urls := []string{
		"https://api.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://ifconfig.me/ip",
	}
	for _, u := range urls {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "remnanode-watchdog/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()

		s := strings.TrimSpace(string(b))
		ip := net.ParseIP(s)
		if ip != nil && ip.To4() != nil && !isPrivateIPv4(ip.To4()) {
			return ip.To4().String()
		}
	}
	return ""
}

func isPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// 10.0.0.0/8
	if ip4[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	// 127.0.0.0/8
	if ip4[0] == 127 {
		return true
	}
	return false
}

type FirewallBanner struct {
	cmdTemplate string
	timeout     time.Duration
	dedupTTL    time.Duration

	mu   sync.Mutex
	seen map[string]int64
}

func NewFirewallBanner(cmdTemplate string, timeout, dedupTTL time.Duration) *FirewallBanner {
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	if dedupTTL <= 0 {
		dedupTTL = 3600 * time.Second
	}
	return &FirewallBanner{
		cmdTemplate: strings.TrimSpace(cmdTemplate),
		timeout:     timeout,
		dedupTTL:    dedupTTL,
		seen:        make(map[string]int64, 1024),
	}
}

func (b *FirewallBanner) BanIPv4(parent context.Context, ip string) (bool, string) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To4() == nil || isPrivateIPv4(parsed.To4()) {
		return false, "invalid or private ip"
	}

	now := time.Now().Unix()

	b.mu.Lock()
	if last, ok := b.seen[ip]; ok {
		if now-last < int64(b.dedupTTL.Seconds()) {
			b.mu.Unlock()
			return true, "" // already handled recently
		}
	}
	b.mu.Unlock()

	if b.cmdTemplate == "" {
		return false, "NFT_BAN_CMD is empty"
	}

	cmdLine := strings.ReplaceAll(b.cmdTemplate, "%IP%", ip)
	args, err := splitCommand(cmdLine)
	if err != nil || len(args) == 0 {
		return false, "bad NFT_BAN_CMD"
	}

	ctx, cancel := context.WithTimeout(parent, b.timeout)
	defer cancel()

	out, runErr := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	outStr := strings.TrimSpace(string(out))

	// nft может ругаться если элемент уже есть — считаем это успехом
	if runErr != nil {
		low := strings.ToLower(outStr)
		if strings.Contains(low, "exists") {
			runErr = nil
			outStr = ""
		}
	}

	if runErr == nil {
		b.mu.Lock()
		b.seen[ip] = now
		b.mu.Unlock()
		return true, ""
	}

	if len(outStr) > 300 {
		outStr = outStr[:300] + "…"
	}
	return false, outStr
}

type nftAddElementTemplate struct {
	prefix []string // например: ["nft"] или ["sudo","nft"]
	family string   // inet/ip/ip6
	table  string
	set    string
}

// parseNftAddElementTemplate пытается распарсить NFT_BAN_CMD формата:
// nft add element <family> <table> <set> { %IP% }
func parseNftAddElementTemplate(cmdTemplate string) (nftAddElementTemplate, bool) {
	cmdTemplate = strings.TrimSpace(cmdTemplate)
	if cmdTemplate == "" {
		return nftAddElementTemplate{}, false
	}
	args, err := splitCommand(cmdTemplate)
	if err != nil || len(args) < 6 {
		return nftAddElementTemplate{}, false
	}

	for i := 0; i+4 < len(args); i++ {
		if args[i] == "add" && args[i+1] == "element" {
			prefix := args[:i]
			if len(prefix) == 0 {
				return nftAddElementTemplate{}, false
			}
			family := strings.TrimSpace(args[i+2])
			table := strings.TrimSpace(args[i+3])
			set := strings.TrimSpace(args[i+4])
			if family == "" || table == "" || set == "" {
				return nftAddElementTemplate{}, false
			}
			return nftAddElementTemplate{
				prefix: prefix,
				family: family,
				table:  table,
				set:    set,
			}, true
		}
	}

	return nftAddElementTemplate{}, false
}

func nftLooksMissing(out string) bool {
	low := strings.ToLower(out)
	// типичные сообщения nft при отсутствии объектов
	return strings.Contains(low, "no such file") ||
		strings.Contains(low, "does not exist") ||
		strings.Contains(low, "not found") ||
		strings.Contains(low, "unknown table") ||
		strings.Contains(low, "unknown set") ||
		strings.Contains(low, "unknown chain")
}

func nftLooksExists(out string) bool {
	low := strings.ToLower(out)
	// типичные сообщения nft при попытке создать уже существующее
	return strings.Contains(low, "file exists") || strings.Contains(low, "exists")
}

// runNftWithTimeout запускает prefix[0] с аргументами prefix[1:]+args и возвращает stdout/stderr (trimmed)
func runNftWithTimeout(parent context.Context, timeout time.Duration, prefix []string, args ...string) (string, error) {
	if len(prefix) == 0 {
		return "", errors.New("empty nft prefix")
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, prefix[0], append(prefix[1:], args...)...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// EnsureNftables гарантирует наличие table/set/chain/rule под ban set.
// ВНИМАНИЕ: создаёт базовую цепочку hook input и drop-правило, если их нет.
func (b *FirewallBanner) EnsureNftables(parent context.Context) (bool, string) {
	if b == nil {
		return false, "banner is nil"
	}
	if strings.TrimSpace(b.cmdTemplate) == "" {
		return true, "" // ничего не настраиваем
	}

	tmpl, ok := parseNftAddElementTemplate(b.cmdTemplate)
	if !ok {
		return false, "cannot parse NFT_BAN_CMD; expected something like: nft add element <family> <table> <set> { %IP% }"
	}

	family := strings.TrimSpace(tmpl.family)
	table := strings.TrimSpace(tmpl.table)
	setName := strings.TrimSpace(tmpl.set)

	famLow := strings.ToLower(family)
	if famLow != "inet" && famLow != "ip" && famLow != "ip6" {
		return false, "unsupported nft family: " + family
	}

	// Подбираем тип set и префикс протокола для правила
	addrType := "ipv4_addr"
	ruleProto := "ip"
	if famLow == "ip6" {
		addrType = "ipv6_addr"
		ruleProto = "ip6"
	}

	// Таймаут для ensure делаем чуть щедрее, чем для единичного бана
	ensureTimeout := b.timeout
	if ensureTimeout < 2*time.Second {
		ensureTimeout = 2 * time.Second
	}

	// 1) Table
	if out, err := runNftWithTimeout(parent, ensureTimeout, tmpl.prefix, "list", "table", family, table); err != nil {
		if nftLooksMissing(out) {
			out2, err2 := runNftWithTimeout(parent, ensureTimeout, tmpl.prefix, "add", "table", family, table)
			if err2 != nil && !nftLooksExists(out2) {
				return false, fmt.Sprintf("create table failed: %v: %s", err2, out2)
			}
		} else {
			return false, fmt.Sprintf("list table failed: %v: %s", err, out)
		}
	}

	// 2) Set
	if out, err := runNftWithTimeout(parent, ensureTimeout, tmpl.prefix, "list", "set", family, table, setName); err != nil {
		if nftLooksMissing(out) {
			// nft add set inet remnaguard blocked_ipv4 { type ipv4_addr; flags interval; }
			args := []string{"add", "set", family, table, setName, "{", "type", addrType + ";", "flags", "interval;", "}"}
			out2, err2 := runNftWithTimeout(parent, ensureTimeout, tmpl.prefix, args...)
			if err2 != nil && !nftLooksExists(out2) {
				return false, fmt.Sprintf("create set failed: %v: %s", err2, out2)
			}
		} else {
			return false, fmt.Sprintf("list set failed: %v: %s", err, out)
		}
	}

	// 3) Base chain (hook input)
	chainName := "remnaguard_input"
	if out, err := runNftWithTimeout(parent, ensureTimeout, tmpl.prefix, "list", "chain", family, table, chainName); err != nil {
		if nftLooksMissing(out) {
			// nft add chain inet remnaguard remnaguard_input { type filter hook input priority -100; policy accept; }
			args := []string{
				"add", "chain", family, table, chainName,
				"{", "type", "filter", "hook", "input", "priority", "-100;", "policy", "accept;", "}",
			}
			out2, err2 := runNftWithTimeout(parent, ensureTimeout, tmpl.prefix, args...)
			if err2 != nil && !nftLooksExists(out2) {
				return false, fmt.Sprintf("create chain failed: %v: %s", err2, out2)
			}
		} else {
			return false, fmt.Sprintf("list chain failed: %v: %s", err, out)
		}
	}

	// 4) Drop rule, если отсутствует
	out, err := runNftWithTimeout(parent, ensureTimeout, tmpl.prefix, "-a", "list", "chain", family, table, chainName)
	if err != nil {
		return false, fmt.Sprintf("list chain for rule failed: %v: %s", err, out)
	}

	needle := ruleProto + " saddr @" + setName
	// На всякий случай проверяем наличие именно привязки к set и drop.
	hasRule := strings.Contains(out, needle) && strings.Contains(out, " drop")

	if !hasRule {
		// nft add rule inet remnaguard remnaguard_input ip saddr @blocked_ipv4 drop
		out2, err2 := runNftWithTimeout(parent, ensureTimeout, tmpl.prefix,
			"add", "rule", family, table, chainName, ruleProto, "saddr", "@"+setName, "drop",
		)
		if err2 != nil && !nftLooksExists(out2) {
			return false, fmt.Sprintf("add drop rule failed: %v: %s", err2, out2)
		}
	}

	return true, ""
}
