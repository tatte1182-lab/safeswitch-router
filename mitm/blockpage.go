package mitm

import "fmt"

// blockPageHTML returns a branded SafeSwitch block page for the given hostname.
func blockPageHTML(hostname string) []byte {
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SafeSwitch — Site Blocked</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0a0d14;
    color: #e8edf8;
    min-height: 100vh;
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
    max-width: 480px;
    width: 100%%;
    text-align: center;
    box-shadow: 0 24px 80px rgba(0,0,0,0.5);
  }
  .shield {
    width: 72px;
    height: 72px;
    background: rgba(255, 71, 87, 0.12);
    border: 1px solid rgba(255, 71, 87, 0.3);
    border-radius: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 24px;
    font-size: 32px;
  }
  h1 {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: -0.03em;
    margin-bottom: 12px;
    color: #e8edf8;
  }
  .domain {
    font-size: 13px;
    color: #ff4757;
    background: rgba(255, 71, 87, 0.1);
    border: 1px solid rgba(255, 71, 87, 0.25);
    border-radius: 8px;
    padding: 6px 14px;
    display: inline-block;
    margin-bottom: 18px;
    font-family: 'SF Mono', Monaco, monospace;
  }
  p {
    color: #97a6c3;
    font-size: 14px;
    line-height: 1.65;
    margin-bottom: 28px;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: #54637f;
    border: 1px solid #1e2a42;
    border-radius: 999px;
    padding: 6px 14px;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%%;
    background: #00c8ff;
    box-shadow: 0 0 10px #00c8ff;
  }
</style>
</head>
<body>
<div class="card">
  <div class="shield">🛡</div>
  <h1>Site Blocked by SafeSwitch</h1>
  <div class="domain">%s</div>
  <p>
    This website has been blocked by your family's SafeSwitch safety settings.
    If you think this is a mistake, ask a parent to review the filter settings.
  </p>
  <div class="badge">
    <span class="dot"></span>
    SafeSwitch Family Security
  </div>
</div>
</body>
</html>`, hostname))
}

// blockResponse returns a full HTTP/1.1 403 response with the block page body.
func blockResponse(hostname string) []byte {
	body := blockPageHTML(hostname)
	header := fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		len(body),
	)
	return append([]byte(header), body...)
}
