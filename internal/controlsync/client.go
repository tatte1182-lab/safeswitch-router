package controlsync

import (
"bytes"
"context"
"fmt"
"io"
"net/http"
"time"
)

type client struct {
baseURL   string
nodeToken string
anonKey   string
logger    Logger
http      *http.Client
}

func newClient(baseURL, nodeToken, anonKey string, logger Logger) *client {
return &client{
baseURL:   baseURL,
nodeToken: nodeToken,
anonKey:   anonKey,
logger:    logger,
http: &http.Client{
Timeout: 10 * time.Second,
},
}
}

func (c *client) post(ctx context.Context, path string, body []byte) ([]byte, int, error) {
return c.do(ctx, http.MethodPost, path, body)
}

func (c *client) get(ctx context.Context, path string) ([]byte, int, error) {
return c.do(ctx, http.MethodGet, path, nil)
}


func (c *client) postREST(ctx context.Context, path string, body []byte) ([]byte, int, error) {
url := c.baseURL + path
delays := []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second}
var lastErr error
for attempt, delay := range delays {
if delay > 0 {
select {
case <-ctx.Done():
return nil, 0, ctx.Err()
case <-time.After(delay):
}
}
var bodyReader io.Reader
if body != nil {
bodyReader = bytes.NewReader(body)
}
req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
if err != nil {
return nil, 0, fmt.Errorf("build request: %w", err)
}
req.Header.Set("Authorization", "Bearer "+c.anonKey)
req.Header.Set("apikey", c.anonKey)
req.Header.Set("Content-Type", "application/json")
req.Header.Set("Accept", "application/json")
resp, err := c.http.Do(req)
if err != nil {
lastErr = fmt.Errorf("http: %w", err)
c.logger.Printf("[controlsync] POST %s attempt=%d failed: %v", path, attempt+1, lastErr)
continue
}
defer resp.Body.Close()
respBody, err := io.ReadAll(resp.Body)
if err != nil {
lastErr = fmt.Errorf("read response body: %w", err)
c.logger.Printf("[controlsync] POST %s attempt=%d failed: %v", path, attempt+1, lastErr)
continue
}
if resp.StatusCode >= 400 {
lastErr = fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(respBody), 200))
c.logger.Printf("[controlsync] POST %s attempt=%d failed: %v", path, attempt+1, lastErr)
continue
}
return respBody, resp.StatusCode, nil
}
return nil, 0, fmt.Errorf("all attempts failed for POST %s: %w", path, lastErr)
}

func (c *client) patch(ctx context.Context, path string, body []byte) ([]byte, int, error) {
return c.do(ctx, http.MethodPatch, path, body)
}

func (c *client) do(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
url := c.baseURL + path
delays := []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second}
var lastErr error
for attempt, delay := range delays {
if delay > 0 {
select {
case <-ctx.Done():
return nil, 0, ctx.Err()
case <-time.After(delay):
}
}
respBody, status, err := c.doOnce(ctx, method, url, body)
if err == nil {
return respBody, status, nil
}
lastErr = err
c.logger.Printf("[controlsync] %s %s attempt=%d failed: %v", method, path, attempt+1, err)
}
return nil, 0, fmt.Errorf("all attempts failed for %s %s: %w", method, path, lastErr)
}

func (c *client) doOnce(ctx context.Context, method, url string, body []byte) ([]byte, int, error) {
var bodyReader io.Reader
if body != nil {
bodyReader = bytes.NewReader(body)
}
req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
if err != nil {
return nil, 0, fmt.Errorf("build request: %w", err)
}
req.Header.Set("Authorization", "Bearer "+c.nodeToken)
req.Header.Set("apikey", c.anonKey)
req.Header.Set("Content-Type", "application/json")
req.Header.Set("Accept", "application/json")
resp, err := c.http.Do(req)
if err != nil {
return nil, 0, fmt.Errorf("http: %w", err)
}
defer resp.Body.Close()
respBody, err := io.ReadAll(resp.Body)
if err != nil {
return nil, resp.StatusCode, fmt.Errorf("read response body: %w", err)
}
if resp.StatusCode >= 400 {
return nil, resp.StatusCode, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(respBody), 200))
}
return respBody, resp.StatusCode, nil
}

func truncate(s string, n int) string {
if len(s) <= n {
return s
}
return s[:n] + "..."
}
