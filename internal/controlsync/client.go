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
	baseURL         string
	nodeToken       string
	anonKey         string
	serviceRoleKey  string // ← NEW: bypasses RLS for control-plane writes
	logger          Logger
	http            *http.Client
}

func newClient(baseURL, nodeToken, anonKey, serviceRoleKey string, logger Logger) *client {

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
		baseURL:        baseURL,
		nodeToken:      nodeToken,
		anonKey:        anonKey,
		serviceRoleKey: serviceRoleKey,
		logger:         logger,
		http: &http.Client{
			Timeout:   60 * time.Second, // bumped from 10s — NRD ingest streams ~35 MB
			Transport: transport,
		},
	}
}

//
// ── Auth modes
//

type authMode int

const (
	authAnon        authMode = 0 // public REST reads (default)
	authNodeToken   authMode = 1 // Edge Functions
	authServiceRole authMode = 2 // RLS-protected control-plane writes
)

//
// ── Options for advanced calls (variadic, zero-cost when unused)
//

// reqOpt mutates a request before it goes out, or annotates how the response
// should be processed. Existing callers don't pass any opts and behave
// identically to before.
type reqOpt func(*reqOpts)

type reqOpts struct {
	auth          authMode
	extraHeaders  map[string]string
	wantRespHdrs  bool // if true, doOnce returns response headers too
}

// withAuth overrides the default auth mode. The non-Opts methods pick anon
// or node-token based on which method was called; this is for callers that
// need service-role specifically.
func withAuth(a authMode) reqOpt {
	return func(o *reqOpts) { o.auth = a }
}

// withHeader sets one extra header on the outgoing request. Multiple
// withHeader opts compose. Used for Prefer, Range, Accept overrides.
func withHeader(key, value string) reqOpt {
	return func(o *reqOpts) {
		if o.extraHeaders == nil {
			o.extraHeaders = make(map[string]string, 2)
		}
		o.extraHeaders[key] = value
	}
}

// withRespHeaders signals the caller wants response headers returned.
// Used by NRD prune to read Content-Range for the deletion count.
func withRespHeaders() reqOpt {
	return func(o *reqOpts) { o.wantRespHdrs = true }
}

func resolveOpts(defaultAuth authMode, opts []reqOpt) reqOpts {
	r := reqOpts{auth: defaultAuth}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

//
// ── Edge Function methods (Bearer = nodeToken). Existing API unchanged.
//

func (c *client) post(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	body2, status, _, err := c.doWithRetry(ctx, http.MethodPost, path, body, resolveOpts(authNodeToken, nil))
	return body2, status, err
}

func (c *client) get(ctx context.Context, path string) ([]byte, int, error) {
	body2, status, _, err := c.doWithRetry(ctx, http.MethodGet, path, nil, resolveOpts(authNodeToken, nil))
	return body2, status, err
}

func (c *client) patch(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	body2, status, _, err := c.doWithRetry(ctx, http.MethodPatch, path, body, resolveOpts(authNodeToken, nil))
	return body2, status, err
}

//
// ── REST API methods (default Bearer = anonKey). Existing API unchanged.
//
// All methods now accept variadic options. Existing callers pass none and
// behave exactly as before. NRD code passes withAuth/withHeader as needed.
//

func (c *client) getREST(ctx context.Context, path string, opts ...reqOpt) ([]byte, int, error) {
	body, status, _, err := c.doWithRetry(ctx, http.MethodGet, path, nil, resolveOpts(authAnon, opts))
	return body, status, err
}

func (c *client) postREST(ctx context.Context, path string, body []byte, opts ...reqOpt) ([]byte, int, error) {
	body2, status, _, err := c.doWithRetry(ctx, http.MethodPost, path, body, resolveOpts(authAnon, opts))
	return body2, status, err
}

func (c *client) patchREST(ctx context.Context, path string, body []byte, opts ...reqOpt) ([]byte, int, error) {
	body2, status, _, err := c.doWithRetry(ctx, http.MethodPatch, path, body, resolveOpts(authAnon, opts))
	return body2, status, err
}

// deleteREST is new — used by NRD prune. Returns response headers when
// withRespHeaders() is passed so the caller can read Content-Range.
func (c *client) deleteREST(ctx context.Context, path string, opts ...reqOpt) ([]byte, int, http.Header, error) {
	return c.doWithRetry(ctx, http.MethodDelete, path, nil, resolveOpts(authAnon, opts))
}

// getRESTWithHeaders is the variant that also returns response headers.
// Separate name from getREST so existing callers' return-value count is
// preserved and the addition is opt-in. Used by NRD pagination if we ever
// need to read Content-Range from list responses.
func (c *client) getRESTWithHeaders(ctx context.Context, path string, opts ...reqOpt) ([]byte, int, http.Header, error) {
	resolved := resolveOpts(authAnon, opts)
	resolved.wantRespHdrs = true
	return c.doWithRetry(ctx, http.MethodGet, path, nil, resolved)
}

//
// ── Unified retry engine (clean + correct) — now header-aware
//

func (c *client) doWithRetry(
	ctx context.Context,
	method, path string,
	body []byte,
	opts reqOpts,
) ([]byte, int, http.Header, error) {
	url := c.baseURL + path

	delays := []time.Duration{0, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second}
	var lastErr error

	for attempt, delay := range delays {

		if delay > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		respBody, status, hdrs, err := c.doOnce(ctx, method, url, path, body, opts)
		if err == nil {
			return respBody, status, hdrs, nil
		}

		lastErr = err
		c.logger.Printf("[client] %s %s attempt=%d failed: %v", method, path, attempt+1, err)
	}

	return nil, 0, nil, fmt.Errorf("all attempts failed for %s %s: %w", method, path, lastErr)
}

//
// ── Single request execution
//

func (c *client) doOnce(
	ctx context.Context,
	method, url, path string,
	body []byte,
	opts reqOpts,
) ([]byte, int, http.Header, error) {

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("build request: %w", err)
	}

	// Auth (one of three modes).
	switch opts.auth {
	case authNodeToken:
		req.Header.Set("Authorization", "Bearer "+c.nodeToken)
	case authServiceRole:
		// Both Authorization AND apikey must be the service-role key
		// for PostgREST to bypass RLS. Setting only one results in
		// PostgREST falling back to anon's role.
		req.Header.Set("Authorization", "Bearer "+c.serviceRoleKey)
		req.Header.Set("apikey", c.serviceRoleKey)
	default: // authAnon
		req.Header.Set("Authorization", "Bearer "+c.anonKey)
	}

	// apikey: only set if not already set above (service-role overrides).
	if req.Header.Get("apikey") == "" {
		req.Header.Set("apikey", c.anonKey)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if method == http.MethodPatch {
		req.Header.Set("Prefer", "return=representation")
	}

	// Caller-supplied extra headers go LAST so they can override defaults
	// (e.g. NRD upsert overrides Prefer to use merge-duplicates,
	// return=minimal).
	for k, v := range opts.extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode >= 400 {
		// 416 (Range Not Satisfiable) is expected during NRD pagination
		// when we walk past the end. Return it without wrapping in an
		// error so the caller can detect cleanly.
		if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			if opts.wantRespHdrs {
				return respBody, resp.StatusCode, resp.Header, nil
			}
			return respBody, resp.StatusCode, nil, nil
		}
		return nil, resp.StatusCode, nil, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	if opts.wantRespHdrs {
		return respBody, resp.StatusCode, resp.Header, nil
	}
	return respBody, resp.StatusCode, nil, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
