package main

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// cpuStat holds per-core busy/idle jiffy counters from /proc/stat.
type cpuStat struct {
	total []uint64
	idle  []uint64
}

// readCPUStat parses per-core lines ("cpu0 ...") from /proc/stat.
func readCPUStat() *cpuStat {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	cs := &cpuStat{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
			continue
		}
		var tot, idle uint64
		for i := 1; i < len(f); i++ {
			v, _ := strconv.ParseUint(f[i], 10, 64)
			tot += v
			if i == 4 || i == 5 { // idle + iowait
				idle += v
			}
		}
		cs.total = append(cs.total, tot)
		cs.idle = append(cs.idle, idle)
	}
	return cs
}

// cpuPercents returns per-core busy percentages from two samples.
func cpuPercents(prev, cur *cpuStat) []float64 {
	if prev == nil || cur == nil {
		return []float64{}
	}
	n := len(cur.total)
	if len(prev.total) < n {
		n = len(prev.total)
	}
	out := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		dt := float64(cur.total[i] - prev.total[i])
		di := float64(cur.idle[i] - prev.idle[i])
		pct := 0.0
		if dt > 0 {
			pct = 100 * (dt - di) / dt
		}
		if pct < 0 {
			pct = 0
		} else if pct > 100 {
			pct = 100
		}
		out = append(out, roundP(pct, 1))
	}
	return out
}

func roundP(v float64, dp int) float64 {
	m := 1.0
	for i := 0; i < dp; i++ {
		m *= 10
	}
	return float64(int64(v*m+0.5)) / m
}

func procField(path, key string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, key) {
			f := strings.Fields(line)
			if len(f) >= 2 {
				v, _ := strconv.ParseUint(f[1], 10, 64)
				return v
			}
		}
	}
	return 0
}

func firstUint(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

type ifaceStat struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	State   string `json:"state"`
	Carrier bool   `json:"carrier"`
	SpeedMb int    `json:"speedMb"`
	RxBytes uint64 `json:"rxBytes"`
	TxBytes uint64 `json:"txBytes"`
}

func (a *app) readIfaceStats() []ifaceStat {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return []ifaceStat{}
	}
	out := []ifaceStat{}
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		s := ifaceStat{
			Name:    name,
			Role:    a.nicRole(name),
			State:   sysRead(name, "operstate"),
			Carrier: sysRead(name, "carrier") == "1",
			RxBytes: firstUint("/sys/class/net/" + name + "/statistics/rx_bytes"),
			TxBytes: firstUint("/sys/class/net/" + name + "/statistics/tx_bytes"),
		}
		if sp := sysRead(name, "speed"); sp != "" {
			if v, err := strconv.Atoi(sp); err == nil && v > 0 {
				s.SpeedMb = v
			}
		}
		out = append(out, s)
	}
	return out
}

// apiMetrics returns a real-time snapshot for the dashboard. Byte counters are
// cumulative; the client derives throughput from successive polls.
func (a *app) apiMetrics(w http.ResponseWriter, _ *http.Request) {
	cur := readCPUStat()
	a.cpuMu.Lock()
	prev := a.cpuPrev
	a.cpuPrev = cur
	a.cpuMu.Unlock()
	cores := cpuPercents(prev, cur)

	memTotal := procField("/proc/meminfo", "MemTotal:")     // kB
	memAvail := procField("/proc/meminfo", "MemAvailable:") // kB
	swapTotal := procField("/proc/meminfo", "SwapTotal:")
	swapFree := procField("/proc/meminfo", "SwapFree:")
	memUsed := uint64(0)
	if memTotal > memAvail {
		memUsed = memTotal - memAvail
	}

	load1, load5, load15 := 0.0, 0.0, 0.0
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			load1, _ = strconv.ParseFloat(f[0], 64)
			load5, _ = strconv.ParseFloat(f[1], 64)
			load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	uptime := 0.0
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 1 {
			uptime, _ = strconv.ParseFloat(f[0], 64)
		}
	}

	ctCount := firstUint("/proc/sys/net/netfilter/nf_conntrack_count")
	ctMax := firstUint("/proc/sys/net/netfilter/nf_conntrack_max")

	memPct := 0.0
	if memTotal > 0 {
		memPct = roundP(100*float64(memUsed)/float64(memTotal), 1)
	}
	cpuAvg := 0.0
	for _, c := range cores {
		cpuAvg += c
	}
	if len(cores) > 0 {
		cpuAvg = roundP(cpuAvg/float64(len(cores)), 1)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ts":         time.Now().Unix(),
		"cpu":        map[string]any{"cores": cores, "avg": cpuAvg, "load1": load1, "load5": load5, "load15": load15},
		"mem":        map[string]any{"totalMB": memTotal / 1024, "usedMB": memUsed / 1024, "usedPct": memPct},
		"swap":       map[string]any{"totalMB": swapTotal / 1024, "usedMB": (swapTotal - swapFree) / 1024},
		"uptimeSec":  int64(uptime),
		"conntrack":  map[string]any{"count": ctCount, "max": ctMax},
		"interfaces": a.readIfaceStats(),
	})
}
