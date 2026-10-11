// Package health reads the machine's vital signs for the dashboard.
//
// Everything comes straight from the kernel's /proc and /sys files, which the
// unprivileged service user may read. No root helper is involved.
package health

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Boot media, as reported to the UI.
const (
	BootSDCard  = "sd-card"
	BootDisk    = "disk"
	BootUnknown = "unknown"
)

type Snapshot struct {
	CPUPercent       float64  `json:"cpuPercent"`
	MemoryTotalBytes uint64   `json:"memoryTotalBytes"`
	MemoryUsedBytes  uint64   `json:"memoryUsedBytes"`
	DiskTotalBytes   uint64   `json:"diskTotalBytes"`
	DiskUsedBytes    uint64   `json:"diskUsedBytes"`
	TemperatureC     *float64 `json:"temperatureC"` // null when the machine has no sensor
	UptimeSeconds    int64    `json:"uptimeSeconds"`
	Hostname         string   `json:"hostname"`
	OS               string   `json:"os"`
	Kernel           string   `json:"kernel"`
	Model            string   `json:"model"`
	BootMedium       string   `json:"bootMedium"`
}

// Monitor samples processor use in the background and reads the rest on demand.
type Monitor struct {
	// root is "/" in production. Tests point it at a folder of sample files.
	root   string
	statfs func(path string, buf *syscall.Statfs_t) error

	mu         sync.Mutex
	cpuPercent float64
	lastBusy   uint64
	lastTotal  uint64
	haveSample bool
}

func NewMonitor() *Monitor {
	return &Monitor{root: "/", statfs: syscall.Statfs}
}

// Run samples processor use every interval until ctx is cancelled.
// Processor use is a rate, so it needs two readings some time apart.
func (m *Monitor) Run(ctx context.Context, interval time.Duration) {
	m.sampleCPU()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sampleCPU()
		}
	}
}

func (m *Monitor) sampleCPU() {
	busy, total, err := m.readCPUTimes()
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.haveSample && total > m.lastTotal {
		m.cpuPercent = 100 * float64(busy-m.lastBusy) / float64(total-m.lastTotal)
	}
	m.lastBusy, m.lastTotal, m.haveSample = busy, total, true
}

// Snapshot returns the current readings. A value that cannot be read is left
// at zero (or null for temperature) rather than failing the whole snapshot:
// a dashboard with one empty tile is more useful than no dashboard.
func (m *Monitor) Snapshot() Snapshot {
	var s Snapshot

	m.mu.Lock()
	s.CPUPercent = m.cpuPercent
	m.mu.Unlock()

	s.MemoryTotalBytes, s.MemoryUsedBytes = m.readMemory()
	s.DiskTotalBytes, s.DiskUsedBytes = m.readDisk()
	s.TemperatureC = m.readTemperature()
	s.UptimeSeconds = m.readUptime()
	s.Hostname, _ = os.Hostname()
	s.OS = m.readOSName()
	s.Kernel = m.readTrimmed("proc/sys/kernel/osrelease")
	s.Model = m.readModel()
	s.BootMedium = m.readBootMedium()
	return s
}

func (m *Monitor) path(rel string) string { return filepath.Join(m.root, rel) }

func (m *Monitor) readTrimmed(rel string) string {
	data, err := os.ReadFile(m.path(rel))
	if err != nil {
		return ""
	}
	// Device-tree strings end in a NUL byte.
	return strings.TrimSpace(string(bytes.TrimRight(data, "\x00")))
}

// readCPUTimes returns the busy and total processor time since boot, in the
// kernel's own units, from the first line of /proc/stat:
//
//	cpu  user nice system idle iowait irq softirq steal guest guest_nice
func (m *Monitor) readCPUTimes() (busy, total uint64, err error) {
	f, err := os.Open(m.path("proc/stat"))
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0, 0, fmt.Errorf("proc/stat is empty")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("unexpected first line in proc/stat")
	}
	var idle uint64
	// Only the first eight values: guest time is already included in user time.
	for i, field := range fields[1:min(len(fields), 9)] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("unexpected value in proc/stat: %w", err)
		}
		total += value
		if i == 3 || i == 4 { // idle and iowait
			idle += value
		}
	}
	return total - idle, total, nil
}

// readMemory returns total and used memory. "Used" is what applications
// actually hold: memory the kernel only uses as disk cache counts as free,
// which is what MemAvailable expresses.
func (m *Monitor) readMemory() (total, used uint64) {
	f, err := os.Open(m.path("proc/meminfo"))
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	var available uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		kib, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = kib * 1024
		case "MemAvailable:":
			available = kib * 1024
		}
	}
	if available > total {
		return total, 0
	}
	return total, total - available
}

func (m *Monitor) readDisk() (total, used uint64) {
	var fs syscall.Statfs_t
	if err := m.statfs("/", &fs); err != nil {
		return 0, 0
	}
	blockSize := uint64(fs.Bsize)
	total = fs.Blocks * blockSize
	// Bavail, not Bfree: space reserved for root is not available to SGC.
	free := fs.Bavail * blockSize
	if free > total {
		return total, 0
	}
	return total, total - free
}

func (m *Monitor) readTemperature() *float64 {
	raw := m.readTrimmed("sys/class/thermal/thermal_zone0/temp")
	if raw == "" {
		return nil
	}
	milli, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil
	}
	celsius := milli / 1000
	return &celsius
}

func (m *Monitor) readUptime() int64 {
	fields := strings.Fields(m.readTrimmed("proc/uptime"))
	if len(fields) == 0 {
		return 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(seconds)
}

func (m *Monitor) readOSName() string {
	f, err := os.Open(m.path("etc/os-release"))
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(value, `"`)
		}
	}
	return ""
}

// readModel returns the hardware model: the device tree on a Raspberry Pi,
// the firmware's product name on a PC or virtual machine.
func (m *Monitor) readModel() string {
	if model := m.readTrimmed("proc/device-tree/model"); model != "" {
		return model
	}
	return m.readTrimmed("sys/class/dmi/id/product_name")
}

// readBootMedium looks at which device the root filesystem is on. An SD card
// wears out much faster than a disk, so the dashboard shows which one it is.
func (m *Monitor) readBootMedium() string {
	f, err := os.Open(m.path("proc/self/mounts"))
	if err != nil {
		return BootUnknown
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[1] != "/" {
			continue
		}
		device := fields[0]
		switch {
		case strings.HasPrefix(device, "/dev/mmcblk"):
			return BootSDCard
		case strings.HasPrefix(device, "/dev/sd"),
			strings.HasPrefix(device, "/dev/nvme"),
			strings.HasPrefix(device, "/dev/vd"):
			return BootDisk
		}
	}
	return BootUnknown
}
