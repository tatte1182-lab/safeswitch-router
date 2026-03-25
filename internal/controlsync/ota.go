package controlsync

import (
"context"
"crypto/sha256"
"encoding/hex"
"fmt"
"io"
"net/http"
"os"
"os/exec"
"path/filepath"
"runtime"
"time"
)

type OTAPayload struct {
URL     string `json:"url"`
SHA256  string `json:"sha256"`
Version string `json:"version"`
}

func ApplyOTA(ctx context.Context, payload OTAPayload, logger Logger) error {
if payload.URL == "" {
return fmt.Errorf("ota: url is required")
}
if payload.SHA256 == "" {
return fmt.Errorf("ota: sha256 is required")
}
logger.Printf("[ota] downloading version=%s from=%s", payload.Version, payload.URL)
tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("ss-router-update-%d", time.Now().UnixNano()))
if err := downloadFile(ctx, payload.URL, tmpPath); err != nil {
return fmt.Errorf("ota: download: %w", err)
}
defer os.Remove(tmpPath)
if err := verifySHA256(tmpPath, payload.SHA256); err != nil {
return fmt.Errorf("ota: integrity check failed: %w", err)
}
logger.Printf("[ota] integrity verified sha256=%s", payload.SHA256[:16]+"...")
execPath, err := os.Executable()
if err != nil {
return fmt.Errorf("ota: resolve executable: %w", err)
}
execPath, err = filepath.EvalSymlinks(execPath)
if err != nil {
return fmt.Errorf("ota: eval symlinks: %w", err)
}
if err := os.Chmod(tmpPath, 0o755); err != nil {
return fmt.Errorf("ota: chmod: %w", err)
}
if err := os.Rename(tmpPath, execPath); err != nil {
return fmt.Errorf("ota: swap binary: %w", err)
}
logger.Printf("[ota] binary swapped path=%s version=%s - restarting", execPath, payload.Version)
go func() {
time.Sleep(500 * time.Millisecond)
restartProcess(logger)
}()
return nil
}

func downloadFile(ctx context.Context, url, destPath string) error {
req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
if err != nil {
return fmt.Errorf("build request: %w", err)
}
resp, err := http.DefaultClient.Do(req)
if err != nil {
return fmt.Errorf("get: %w", err)
}
defer resp.Body.Close()
if resp.StatusCode != http.StatusOK {
return fmt.Errorf("http %d", resp.StatusCode)
}
f, err := os.Create(destPath)
if err != nil {
return fmt.Errorf("create temp file: %w", err)
}
defer f.Close()
if _, err := io.Copy(f, resp.Body); err != nil {
return fmt.Errorf("write: %w", err)
}
return nil
}

func verifySHA256(path, expected string) error {
f, err := os.Open(path)
if err != nil {
return fmt.Errorf("open: %w", err)
}
defer f.Close()
h := sha256.New()
if _, err := io.Copy(h, f); err != nil {
return fmt.Errorf("hash: %w", err)
}
actual := hex.EncodeToString(h.Sum(nil))
if actual != expected {
return fmt.Errorf("sha256 mismatch: got %s want %s", actual[:16]+"...", expected[:16]+"...")
}
return nil
}

func restartProcess(logger Logger) {
if runtime.GOOS == "linux" {
if err := exec.Command("systemctl", "restart", "ss-router").Run(); err == nil {
return
}
if err := exec.Command("/etc/init.d/ss-router", "restart").Run(); err == nil {
return
}
}
logger.Printf("[ota] falling back to os.Exit(0)")
os.Exit(0)
}
