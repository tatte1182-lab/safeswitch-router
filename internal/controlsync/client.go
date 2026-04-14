package controlsync

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
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

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,

		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,

		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &client{
		baseURL:   baseURL,
		nodeToken: nodeToken,
		anonKey:   anonKey,
		logger:    logger,
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
	}
}

//
// ── Edge Function methods (Bearer = nodeToken)
//

func (c *client) post(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	return c.doWithRetry(ctx, http.MethodPost, path, body, true)
}

func (c *client) get(ctx context.Context, path string) ([]byte, int, error) {
	return c.doWithRetry(ctx, http.MethodGet, path, nil, true)
}

func (c *client) patch(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	return c.doWithRetry(ctx, http.MethodPatch, path, body, true)
}

//
// ── REST API methods (Bearer = anonKey)
//

func (c *client) getREST(ctx context.Context, path string) ([]byte, int, error) {
	return c.doWithRetry(ctx, http.MethodGet, path, nil, false)
}

func (c *client) patchREST(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	return c.doWithRetry(ctx, http.MethodPatch, path, body, false)
}

func (c *client) postREST(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	return c.doWithRetry(ctx, http.MethodPost, path, body, false)
}

//
// ── Unified retry engine (clean + correct)
//

func (c *client) doWithRetry(ctx context.Context, method, path string, body []byte, useNodeToken bool) ([]byte, int, error) {
	url := c.baseURL + path

	delays := []time.Duration{0, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second}
	var lastErr error

	for attempt, delay := range delays {

		if delay > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(delay):
			}
		}

		respBody, status, err := c.doOnce(ctx, method, url, path, body, useNodeToken)
		if err == nil {
			return respBody, status, nil
		}

		lastErr = err
		c.logger.Printf("[client] %s %s attempt=%d failed: %v", method, path, attempt+1, err)
	}

	return nil, 0, fmt.Errorf("all attempts failed for %s %s: %w", method, path, lastErr)
}

//
// ── Single request execution
//

func (c *client) doOnce(ctx context.Context, method, url, path string, body []byte, useNodeToken bool) ([]byte, int, error) {

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}

	// Auth
	if useNodeToken {
		req.Header.Set("Authorization", "Bearer "+c.nodeToken)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.anonKey)
	}

	req.Header.Set("apikey", c.anonKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if method == http.MethodPatch {
		req.Header.Set("Prefer", "return=representation")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read body: %w", err)
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