// Package upnp provides automatic UPnP port mapping for the WireGuard endpoint.
// On startup it discovers the home router via UPnP/IGD and requests a port
// mapping for 51820/UDP → this host. The mapping is renewed every hour and
// released cleanly on shutdown.
//
// If UPnP is unavailable (router has it disabled, or node is on a VPS),
// the service logs a warning and exits cleanly — the VPS relay handles WAN
// connectivity in that case. No impact on the rest of the node.
package upnp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	renewEvery      = 45 * time.Minute // renew before the 1h lease expires
	mappingDuration = 3600             // seconds — standard UPnP lease
	ssdpAddr        = "239.255.255.250:1900"
	ssdpTimeout     = 3 * time.Second
)

type Logger interface {
	Printf(format string, v ...any)
}

// Service manages a UPnP port mapping for the WireGuard port.
type Service struct {
	port        int
	description string
	logger      Logger

	mu          sync.Mutex
	gatewayURL  string
	externalIP  string
	internalIP  string
	mapped      bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(wireguardPort int, logger Logger) *Service {
	return &Service{
		port:        wireguardPort,
		description: "SafeSwitch-WireGuard",
		logger:      logger,
	}
}

func (s *Service) Name() string { return "upnp" }

func (s *Service) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	// Try initial mapping — non-fatal if it fails
	if err := s.tryMap(runCtx); err != nil {
		s.logger.Printf("[upnp] not available: %v (VPS relay will handle WAN)", err)
		cancel()
		return nil // not an error — node still works via relay
	}

	// Renew loop
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(renewEvery)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if err := s.tryMap(runCtx); err != nil {
					s.logger.Printf("[upnp] renewal failed: %v", err)
				}
			}
		}
	}()

	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	s.release()
	return nil
}

func (s *Service) Health(ctx context.Context) error { return nil }

// ExternalIP returns the public IP discovered via UPnP, or empty string.
func (s *Service) ExternalIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.externalIP
}

// IsMapped returns true if a port mapping is currently active.
func (s *Service) IsMapped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mapped
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (s *Service) tryMap(ctx context.Context) error {
	// 1. Discover gateway
	gwURL, err := s.discover(ctx)
	if err != nil {
		return fmt.Errorf("discover gateway: %w", err)
	}

	// 2. Get our LAN IP
	lanIP, err := s.lanIP()
	if err != nil {
		return fmt.Errorf("get LAN IP: %w", err)
	}

	// 3. Add port mapping
	if err := s.addMapping(ctx, gwURL, lanIP); err != nil {
		return fmt.Errorf("add mapping: %w", err)
	}

	// 4. Get external IP
	extIP, err := s.getExternalIP(ctx, gwURL)
	if err != nil {
		s.logger.Printf("[upnp] could not get external IP: %v", err)
	}

	s.mu.Lock()
	s.gatewayURL = gwURL
	s.internalIP = lanIP
	s.externalIP = extIP
	s.mapped = true
	s.mu.Unlock()

	s.logger.Printf("[upnp] mapped %s:%d/UDP → %s:%d (external IP: %s)",
		lanIP, s.port, lanIP, s.port, extIP)
	return nil
}

func (s *Service) release() {
	s.mu.Lock()
	gwURL := s.gatewayURL
	mapped := s.mapped
	s.mapped = false
	s.mu.Unlock()

	if !mapped || gwURL == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.deleteMapping(ctx, gwURL); err != nil {
		s.logger.Printf("[upnp] release mapping failed: %v", err)
	} else {
		s.logger.Printf("[upnp] port mapping released")
	}
}

// discover sends an SSDP M-SEARCH and returns the gateway's control URL.
func (s *Service) discover(ctx context.Context) (string, error) {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(ssdpTimeout)
	}
	_ = conn.SetDeadline(deadline)

	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"

	dst, _ := net.ResolveUDPAddr("udp4", ssdpAddr)
	if _, err := conn.WriteTo([]byte(msg), dst); err != nil {
		return "", err
	}

	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		resp := string(buf[:n])
		if loc := extractHeader(resp, "LOCATION"); loc != "" {
			ctrlURL, err := s.getControlURL(ctx, loc)
			if err == nil && ctrlURL != "" {
				return ctrlURL, nil
			}
		}
	}
	return "", fmt.Errorf("no UPnP gateway found (UPnP may be disabled on router)")
}

// getControlURL fetches the IGD description XML and extracts the WANIPConnection control URL.
func (s *Service) getControlURL(ctx context.Context, locationURL string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(reqCtx, "GET", locationURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	buf := make([]byte, 32768)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Extract WANIPConnection or WANPPPConnection controlURL
	for _, svcType := range []string{"WANIPConnection", "WANPPPConnection"} {
		idx := strings.Index(body, svcType)
		if idx < 0 {
			continue
		}
		sub := body[idx:]
		ctrlIdx := strings.Index(sub, "<controlURL>")
		if ctrlIdx < 0 {
			continue
		}
		end := strings.Index(sub[ctrlIdx:], "</controlURL>")
		if end < 0 {
			continue
		}
		path := sub[ctrlIdx+12 : ctrlIdx+end]

		// Build absolute URL from location base
		base := locationURL[:strings.LastIndex(locationURL, "/")+1]
		if strings.HasPrefix(path, "/") {
			// Absolute path — use just the host
			parts := strings.SplitN(locationURL, "/", 4)
			if len(parts) >= 3 {
				return parts[0] + "//" + parts[2] + path, nil
			}
		}
		return base + path, nil
	}
	return "", fmt.Errorf("no WANIPConnection service in IGD description")
}

// addMapping sends AddPortMapping SOAP action.
func (s *Service) addMapping(ctx context.Context, ctrlURL, internalIP string) error {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>%d</NewExternalPort>
      <NewProtocol>UDP</NewProtocol>
      <NewInternalPort>%d</NewInternalPort>
      <NewInternalClient>%s</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>%s</NewPortMappingDescription>
      <NewLeaseDuration>%d</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>`, s.port, s.port, internalIP, s.description, mappingDuration)

	return s.soapAction(ctx, ctrlURL,
		"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping", body)
}

// deleteMapping sends DeletePortMapping SOAP action.
func (s *Service) deleteMapping(ctx context.Context, ctrlURL string) error {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>%d</NewExternalPort>
      <NewProtocol>UDP</NewProtocol>
    </u:DeletePortMapping>
  </s:Body>
</s:Envelope>`, s.port)

	return s.soapAction(ctx, ctrlURL,
		"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping", body)
}

// getExternalIP sends GetExternalIPAddress SOAP action.
func (s *Service) getExternalIP(ctx context.Context, ctrlURL string) (string, error) {
	body := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>`

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(reqCtx, "POST", ctrlURL, strings.NewReader(body))
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"`)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	respBody := string(buf[:n])

	ip := extractXML(respBody, "NewExternalIPAddress")
	if ip == "" {
		return "", fmt.Errorf("no IP in response")
	}
	return ip, nil
}

func (s *Service) soapAction(ctx context.Context, ctrlURL, action, body string) error {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", ctrlURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s"`, action))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		return fmt.Errorf("SOAP error %d: %s", resp.StatusCode, string(buf[:n]))
	}
	return nil
}

// lanIP returns the local IP used for outbound connections.
func (s *Service) lanIP() (string, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

func extractHeader(resp, key string) string {
	lower := strings.ToLower(resp)
	lowerKey := strings.ToLower(key) + ":"
	idx := strings.Index(lower, lowerKey)
	if idx < 0 {
		return ""
	}
	rest := resp[idx+len(lowerKey):]
	end := strings.IndexAny(rest, "\r\n")
	if end < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

func extractXML(body, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	idx := strings.Index(body, open)
	if idx < 0 {
		return ""
	}
	start := idx + len(open)
	end := strings.Index(body[start:], close)
	if end < 0 {
		return ""
	}
	return body[start : start+end]
}
