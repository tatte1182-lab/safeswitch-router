package health

type Snapshot struct {
	CPUPct  float64 `json:"cpu_pct"`
	MemPct  float64 `json:"mem_pct"`
	DiskPct float64 `json:"disk_pct"`
	Summary string  `json:"summary"`
}
