// internal/sinkhole/sinkhole.go
//
// SafeSwitch Sinkhole Server
//
// When the DNS engine blocks a domain it returns 10.10.0.2 (the sinkhole IP)
// instead of NXDOMAIN. Any HTTP/HTTPS request to that IP hits this server,
// which returns a clean branded "blocked" page — exactly like Cisco Umbrella,
// Circle, or enterprise proxy block pages.
//
// Architecture:
//   DNS query → blocked → returns 10.10.0.2
//   Browser follows → HTTP request to 10.10.0.2:80
//   Sinkhole serves block page with reason + schedule info
//
// HTTPS note: HTTPS requests will show a TLS error before reaching the block
// page because the sinkhole doesn't have a cert for the blocked domain.
// This is the same behavior as all DNS-based blockers. The correct fix for
// HTTPS is a transparent HTTPS proxy with a root CA installed at enrollment
// (Phase 8 compression stack). For now HTTP domains get the clean page,
// HTTPS domains get a browser TLS error which is still a hard block.
//
// Sinkhole IP: 10.10.0.2 — add this as a second address on wg0:
//   ip addr add 10.10.0.2/32 dev wg0
//   (or set in wg-quick PostUp)

package sinkhole

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const (
	SinkholeAddr = "10.10.0.2"
	HTTPPort     = 80
)

// BlockReason is passed through the DNS layer so the sinkhole can show
// a context-aware message. Stored as a query param on redirect.
type BlockReason string

const (
	ReasonSchedule  BlockReason = "schedule"
	ReasonParent    BlockReason = "parent"
	ReasonSafety    BlockReason = "safety"
	ReasonBedtime   BlockReason = "bedtime"
	ReasonDefault   BlockReason = "blocked"
)

// EnsureSinkholeAddr binds 10.10.0.2/32 on the wg0 interface so the
// sinkhole server can listen on that address. Safe to call on restart —
// if the address is already assigned the command exits non-zero and the
// error is logged but not fatal.
func EnsureSinkholeAddr() error {
	cmd := exec.Command("ip", "addr", "add", SinkholeAddr+"/32", "dev", "wg0")
	if out, err := cmd.CombinedOutput(); err != nil {
		// "RTNETLINK answers: File exists" means it's already bound — fine.
		if !strings.Contains(string(out), "already") {
			return fmt.Errorf("ip addr add: %w: %s", err, out)
		}
	}
	return nil
}

// StartSinkhole starts the HTTP block page server on SinkholeAddr:80.
// Call this from your main service supervisor alongside the DNS engine.
func StartSinkhole() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleBlock)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	addr := fmt.Sprintf("%s:%d", SinkholeAddr, HTTPPort)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Bind only on the sinkhole IP so we don't conflict with other services
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("sinkhole: listen %s: %w", addr, err)
	}

	log.Printf("[sinkhole] listening on %s", addr)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[sinkhole] serve error: %v", err)
		}
	}()
	return nil
}

func handleBlock(w http.ResponseWriter, r *http.Request) {
	domain := r.Host
	if domain == "" {
		domain = r.URL.Host
	}
	// Strip port if present
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	// Sanitise — never echo raw input into HTML
	domain = sanitise(domain)

	reason := BlockReason(r.URL.Query().Get("reason"))
	if reason == "" {
		reason = ReasonDefault
	}

	title, body, emoji := resolveContent(reason)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)

	fmt.Fprintf(w, blockPageHTML, emoji, title, domain, body)
}

func resolveContent(reason BlockReason) (title, body, emoji string) {
	switch reason {
	case ReasonSchedule:
		return "Screen time is paused",
			"This site is blocked during your current schedule. Check the SafeSwitch app to see when your next free period starts.",
			"📅"
	case ReasonBedtime:
		return "It's bedtime",
			"Internet is off for the night. Sleep well — your screen time will be back in the morning.",
			"🌙"
	case ReasonParent:
		return "Paused by a parent",
			"A parent has paused your internet access. You can send a check-in from the SafeSwitch app.",
			"⏸"
	case ReasonSafety:
		return "This site is blocked",
			"SafeSwitch has blocked this site because it may be unsafe. If you think this is a mistake, let a parent know.",
			"🛡️"
	default:
		return "This site is blocked",
			"SafeSwitch has blocked access to this site.",
			"🔒"
	}
}

func sanitise(s string) string {
	// Keep only safe domain characters
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' {
			b.WriteRune(c)
		}
	}
	out := b.String()
	if len(out) > 253 {
		out = out[:253]
	}
	return out
}

// blockPageHTML is a single-file self-contained block page.
// Params: %s = emoji, %s = title, %s = blocked domain, %s = body text.
const blockPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SafeSwitch — Site Blocked</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body {
    height: 100%%;
    background: #08090f;
    color: #e8edf8;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }
  .card {
    background: #111520;
    border: 1px solid #1e2a42;
    border-radius: 24px;
    padding: 40px 36px;
    max-width: 440px;
    width: 100%%;
    text-align: center;
    box-shadow: 0 24px 80px rgba(0,0,0,0.5);
  }
  .emoji {
    font-size: 52px;
    display: block;
    margin-bottom: 20px;
    filter: drop-shadow(0 0 20px rgba(0,200,255,0.3));
  }
  .logo {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-bottom: 28px;
  }
  .logo-dot {
    width: 8px; height: 8px;
    border-radius: 50%%;
    background: #00c8ff;
    box-shadow: 0 0 12px #00c8ff;
  }
  .logo-text {
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #00c8ff;
  }
  h1 {
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.04em;
    line-height: 1.2;
    margin-bottom: 12px;
  }
  .domain {
    font-size: 13px;
    color: #54637f;
    font-family: 'SF Mono', 'Fira Code', monospace;
    margin-bottom: 20px;
    word-break: break-all;
  }
  .body-text {
    color: #97a6c3;
    font-size: 15px;
    line-height: 1.65;
    margin-bottom: 32px;
  }
  .divider {
    border: none;
    border-top: 1px solid #1e2a42;
    margin-bottom: 24px;
  }
  .footer {
    font-size: 12px;
    color: #54637f;
    line-height: 1.6;
  }
  .footer strong {
    color: #97a6c3;
  }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-dot"></div>
    <span class="logo-text">SafeSwitch</span>
  </div>
  <span class="emoji">%s</span>
  <h1>%s</h1>
  <div class="domain">%s</div>
  <p class="body-text">%s</p>
  <hr class="divider">
  <p class="footer">
    Protected by <strong>SafeSwitch</strong> · Open the app to check your schedule
  </p>
</div>
</body>
</html>`
