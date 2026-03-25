package dns

import (
"context"
"database/sql"
"strings"
"sync"
)

type Blocklist struct {
mu      sync.RWMutex
domains map[string]struct{}
}

func NewBlocklist() *Blocklist {
return &Blocklist{domains: make(map[string]struct{})}
}

func (b *Blocklist) IsBlocked(domain string) bool {
domain = strings.ToLower(strings.TrimSuffix(domain, "."))
b.mu.RLock()
defer b.mu.RUnlock()
for {
if _, ok := b.domains[domain]; ok {
return true
}
dot := strings.Index(domain, ".")
if dot < 0 {
return false
}
domain = domain[dot+1:]
}
}

func (b *Blocklist) Load(ctx context.Context, db *sql.DB) error {
rows, err := db.QueryContext(ctx, `SELECT domain FROM dns_blocklist`)
if err != nil {
return err
}
defer rows.Close()
fresh := make(map[string]struct{})
for rows.Next() {
var d string
if err := rows.Scan(&d); err != nil {
continue
}
fresh[strings.ToLower(strings.TrimSuffix(d, "."))] = struct{}{}
}
b.mu.Lock()
b.domains = fresh
b.mu.Unlock()
return rows.Err()
}

func (b *Blocklist) Size() int {
b.mu.RLock()
defer b.mu.RUnlock()
return len(b.domains)
}
