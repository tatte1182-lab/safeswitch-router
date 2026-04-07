package dns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// BlockPageServer serves the SafeSwitch block page on the WireGuard gateway
// address (10.10.0.1:80). When a device's internet is paused or a domain is
// blocked, DNS sinkholes A queries to this IP and the browser lands here
// instead of a raw connection error.
type BlockPageServer struct {
	logger      Logger
	bannerFn    func(srcIP string) (title, body string)
	srv         *http.Server
	mu          sync.Mutex
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewBlockPageServer creates the server. bannerFn is called per request to
// return the current banner title and body for the requesting device — it
// reads from the live policy bundle so the page always shows the right reason.
func NewBlockPageServer(logger Logger, bannerFn func(srcIP string) (title, body string)) *BlockPageServer {
	return &BlockPageServer{
		logger:   logger,
		bannerFn: bannerFn,
	}
}

func (b *BlockPageServer) Name() string { return "blockpage" }

func (b *BlockPageServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", b.handleBlock)

	b.srv = &http.Server{
		Addr:         "10.10.0.1:80",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", "10.10.0.1:80")
	if err != nil {
		return fmt.Errorf("blockpage: listen: %w", err)
	}

	srvCtx, cancel := context.WithCancel(ctx)
	b.mu.Lock()
	b.cancel = cancel
	b.mu.Unlock()

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		<-srvCtx.Done()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutCancel()
		b.srv.Shutdown(shutCtx)
	}()

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		if err := b.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			b.logger.Printf("[blockpage] serve error: %v", err)
		}
	}()

	b.logger.Printf("[blockpage] started addr=10.10.0.1:80")
	return nil
}

func (b *BlockPageServer) Stop(ctx context.Context) error {
	b.mu.Lock()
	if b.cancel != nil {
		b.cancel()
	}
	b.mu.Unlock()
	b.wg.Wait()
	b.logger.Printf("[blockpage] stopped")
	return nil
}

func (b *BlockPageServer) Health(ctx context.Context) error { return nil }

func (b *BlockPageServer) handleBlock(w http.ResponseWriter, r *http.Request) {
	srcIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	title := "Internet Paused"
	body := "Access to the internet is currently restricted."
	if b.bannerFn != nil {
		if t, bd := b.bannerFn(srcIP); t != "" {
			title = t
			body = bd
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, blockPageHTML, title, body)
}

// blockPageHTML is the block page template.
// %s[0] = title (e.g. "🏫 School Time")
// %s[1] = body  (e.g. "School hours until 03:00 PM")
const blockPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SafeSwitch</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #060910 0%%, #0d1117 50%%, #060910 100%%);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    color: #e8edf8;
    padding: 24px;
  }
  .card {
    background: rgba(17, 21, 32, 0.95);
    border: 1px solid #1e2a42;
    border-radius: 28px;
    padding: 48px 40px;
    max-width: 420px;
    width: 100%%;
    text-align: center;
    box-shadow: 0 24px 80px rgba(0,0,0,0.5);
  }
  .shield {
    width: 72px;
    height: 72px;
    background: rgba(0, 200, 255, 0.08);
    border: 1px solid rgba(0, 200, 255, 0.25);
    border-radius: 50%%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 28px;
    font-size: 32px;
  }
  .logo {
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: #00c8ff;
    margin-bottom: 20px;
  }
  h1 {
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.04em;
    line-height: 1.2;
    margin-bottom: 12px;
    color: #ffffff;
  }
  p {
    font-size: 15px;
    color: #97a6c3;
    line-height: 1.6;
  }
  .divider {
    border: none;
    border-top: 1px solid #1e2a42;
    margin: 28px 0;
  }
  .footer {
    font-size: 12px;
    color: #54637f;
  }
</style>
</head>
<body>
  <div class="card">
    <div class="logo">SafeSwitch</div>
    <div class="shield">🛡️</div>
    <h1>%s</h1>
    <p>%s</p>
    <hr class="divider">
    <p class="footer">Protected by SafeSwitch Family Safety</p>
  </div>
</body>
</html>`
