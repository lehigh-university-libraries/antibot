package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	lru "github.com/patrickmn/go-cache"
)

type Config struct {
	Window            int64    `json:"window"`
	IPForwardedHeader string   `json:"ip-forwarded-header"`
	IPDepth           int      `json:"ip-depth"`
	GoodBots          []string `json:"good-bots"`
	ProtectParameters bool     `json:"protectParameters"`
	ChallengeTmpl     string   `json:"challenge-tmpl-path"`
	CaptchaProvider   string   `json:"captcha-provider"`
	SiteKey           string   `json:"site-key"`
	SecretKey         string   `json:"secret-key"`
}

type AntiBot struct {
	config        *Config
	verifiedCache *lru.Cache
	botCache      *lru.Cache
	captchaConfig CaptchaConfig
	tmpl          *template.Template
	ipv4Mask      net.IPMask
	ipv6Mask      net.IPMask
}

type CaptchaConfig struct {
	js       string
	key      string
	validate string
}

type captchaResponse struct {
	Success bool `json:"success"`
}

func NewAntiBot(config *Config) (*AntiBot, error) {
	expiration := time.Duration(config.Window) * time.Second
	slog.Debug("Captcha config", "config", config)

	var tmpl *template.Template
	if _, err := os.Stat(config.ChallengeTmpl); os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to parse challenge template: %v", err)
	} else if err != nil {
		return nil, fmt.Errorf("error checking for template file %s: %v", config.ChallengeTmpl, err)
	} else {
		tmpl, err = template.ParseFiles(config.ChallengeTmpl)
		if err != nil {
			return nil, fmt.Errorf("unable to parse challenge template file %s: %v", config.ChallengeTmpl, err)
		}
	}

	ab := AntiBot{
		config:        config,
		botCache:      lru.New(expiration, 1*time.Hour),
		verifiedCache: lru.New(expiration, 1*time.Hour),
		tmpl:          tmpl,
	}

	// set the captcha config based on the provider
	// thanks to https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/4708d76854c7ae95fa7313c46fbe21959be2fff1/pkg/captcha/captcha.go#L39-L55
	// for the struct/idea
	switch config.CaptchaProvider {
	case "hcaptcha":
		ab.captchaConfig = CaptchaConfig{
			js:       "https://hcaptcha.com/1/api.js",
			key:      "h-captcha",
			validate: "https://api.hcaptcha.com/siteverify",
		}
	case "recaptcha":
		ab.captchaConfig = CaptchaConfig{
			js:       "https://www.google.com/recaptcha/api.js",
			key:      "g-recaptcha",
			validate: "https://www.google.com/recaptcha/api/siteverify",
		}
	case "turnstile":
		ab.captchaConfig = CaptchaConfig{
			js:       "https://challenges.cloudflare.com/turnstile/v0/api.js",
			key:      "cf-turnstile",
			validate: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		}
	default:
		return nil, fmt.Errorf("invalid captcha provider: %s", config.CaptchaProvider)
	}

	return &ab, nil
}

func (ab *AntiBot) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		clientIP, _ := ab.getClientIP(req)
		slog.Debug("Checking IP", "ip", clientIP)
		if req.Method == http.MethodPost {
			statusCode := ab.verifyChallengePage(rw, req, clientIP)
			slog.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "status", statusCode, "useragent", req.UserAgent())
			if statusCode == http.StatusOK {
				next.ServeHTTP(rw, req)
			}
			return
		}

		if !ab.shouldApply(req, clientIP) {
			next.ServeHTTP(rw, req)
			return
		}

		slog.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "useragent", req.UserAgent())
		ab.serveChallengePage(rw, req.URL.Path)
	})
}

func (ab *AntiBot) serveChallengePage(rw http.ResponseWriter, destination string) {
	d := map[string]string{
		"SiteKey":     ab.config.SiteKey,
		"FrontendJS":  ab.captchaConfig.js,
		"FrontendKey": ab.captchaConfig.key,
		"Destination": destination,
	}
	rw.WriteHeader(http.StatusTooManyRequests)

	err := ab.tmpl.Execute(rw, d)
	if err != nil {
		slog.Error("Unable to execute go template", "tmpl", ab.config.ChallengeTmpl, "err", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
	}
}

func (ab *AntiBot) verifyChallengePage(rw http.ResponseWriter, req *http.Request, ip string) int {
	err := req.ParseForm()
	if err != nil {
		slog.Error("Failed to parse form", "error", err)
		http.Error(rw, "Bad request", http.StatusBadRequest)
		return http.StatusBadRequest
	}

	response := req.PostFormValue(ab.captchaConfig.key + "-response")
	if response == "" {
		slog.Error("Expected form value not in request")
		http.Error(rw, "Bad request", http.StatusBadRequest)
		return http.StatusBadRequest
	}

	var body = url.Values{}
	body.Add("secret", ab.config.SecretKey)
	body.Add("response", response)
	slog.Debug("Validating", "url", ab.captchaConfig.validate)
	resp, err := http.PostForm(ab.captchaConfig.validate, body)
	if err != nil {
		slog.Error("Unable to validate captcha", "url", ab.captchaConfig.validate, "body", body, "err", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	defer resp.Body.Close()

	var captchaResponse captchaResponse
	err = json.NewDecoder(resp.Body).Decode(&captchaResponse)
	if err != nil {
		slog.Error("Unable to unmarshal captcha response", "url", ab.captchaConfig.validate, "err", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	if !captchaResponse.Success {
		http.Error(rw, "Validation failed", http.StatusForbidden)

		return http.StatusForbidden
	}

	ab.verifiedCache.Set(ip, true, lru.DefaultExpiration)

	return http.StatusOK
}

func (ab *AntiBot) shouldApply(req *http.Request, clientIP string) bool {
	_, verified := ab.verifiedCache.Get(clientIP)
	if verified {
		return false
	}

	if ab.isGoodBot(req, clientIP) {
		return false
	}

	return true
}

func (ab *AntiBot) getClientIP(req *http.Request) (string, string) {
	ip := req.Header.Get(ab.config.IPForwardedHeader)
	if ab.config.IPForwardedHeader != "" && ip != "" {
		components := strings.Split(ip, ",")
		depth := ab.config.IPDepth
		ip = ""
		for i := len(components) - 1; i >= 0; i-- {
			_ip := strings.TrimSpace(components[i])
			if depth == 0 {
				ip = _ip
				break
			}
			depth--
		}
		if ip == "" {
			slog.Debug("No non-exempt IPs in header. req.RemoteAddr", "ipDepth", ab.config.IPDepth, ab.config.IPForwardedHeader, req.Header.Get(ab.config.IPForwardedHeader))
			ip = req.RemoteAddr
		}
	} else {
		if ab.config.IPForwardedHeader != "" {
			slog.Debug("Received a blank header value. Defaulting to real IP")
		}
		ip = req.RemoteAddr
	}
	if strings.Contains(ip, ":") {
		host, _, _ := net.SplitHostPort(ip)
		ip = host
	}

	return ab.ParseIp(ip)
}

func (ab *AntiBot) ParseIp(ip string) (string, string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ip, ip
	}

	// For IPv4 addresses
	if parsedIP.To4() != nil {
		subnet := parsedIP.Mask(ab.ipv4Mask)
		return ip, subnet.String()
	}

	// For IPv6 addresses
	if parsedIP.To16() != nil {
		subnet := parsedIP.Mask(ab.ipv6Mask)
		return ip, subnet.String()
	}

	slog.Warn("Unknown ip version", "ip", ip)

	return ip, ip
}

func (ab *AntiBot) SetIpv4Mask(m int) error {
	if m < 8 || m > 32 {
		return fmt.Errorf("invalid ipv4 mask: %d. Must be between 8 and 32", m)
	}
	ab.ipv4Mask = net.CIDRMask(m, 32)

	return nil
}

func (ab *AntiBot) SetIpv6Mask(m int) error {
	if m < 8 || m > 128 {
		return fmt.Errorf("invalid ipv6 mask: %d. Must be between 8 and 128", m)
	}
	ab.ipv6Mask = net.CIDRMask(m, 128)

	return nil
}

func (ab *AntiBot) isGoodBot(req *http.Request, clientIP string) bool {
	if ab.config.ProtectParameters {
		if len(req.Header.Get("X-Forwarded-Uri")) > 0 {
			return false
		}
	}

	bot, ok := ab.botCache.Get(clientIP)
	if ok {
		return bot.(bool)
	}

	v := IsIpGoodBot(clientIP, ab.config.GoodBots)
	ab.botCache.Set(clientIP, v, lru.DefaultExpiration)
	return v
}
