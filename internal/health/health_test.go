package health

import (
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// newFixture builds a Monitor that reads from a temporary folder holding the
// given files, laid out like the real /proc, /sys and /etc.
func newFixture(t *testing.T, files map[string]string) *Monitor {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Monitor{
		root: root,
		statfs: func(_ string, fs *syscall.Statfs_t) error {
			fs.Bsize = 4096
			fs.Blocks = 1000
			fs.Bfree = 500
			fs.Bavail = 400 // 100 blocks reserved for root
			return nil
		},
	}
}

func writeStat(t *testing.T, m *Monitor, line string) {
	t.Helper()
	if err := os.WriteFile(m.path("proc/stat"), []byte(line+"\ncpu0 1 2 3 4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCPUPercentIsTheBusyShareBetweenTwoSamples(t *testing.T) {
	m := newFixture(t, map[string]string{"proc/stat": ""})

	//                user nice system idle iowait irq softirq steal
	writeStat(t, m, "cpu  100 0 100 700 100 0 0 0 0 0")
	m.sampleCPU()
	if got := m.Snapshot().CPUPercent; got != 0 {
		t.Errorf("after one sample: %v%%, want 0 (a rate needs two readings)", got)
	}

	// 200 more units passed: 50 busy (user+system), 150 idle or waiting.
	writeStat(t, m, "cpu  130 0 120 800 150 0 0 0 0 0")
	m.sampleCPU()
	if got := m.Snapshot().CPUPercent; math.Abs(got-25) > 0.001 {
		t.Errorf("CPUPercent = %v, want 25", got)
	}
}

func TestSnapshotReadsTheMachine(t *testing.T) {
	m := newFixture(t, map[string]string{
		"proc/meminfo":                         "MemTotal:        4000000 kB\nMemFree:          100000 kB\nMemAvailable:    3000000 kB\n",
		"proc/uptime":                          "273845.12 1000000.00\n",
		"proc/sys/kernel/osrelease":            "6.12.47+rpt-rpi-v8\n",
		"proc/device-tree/model":               "Raspberry Pi 4 Model B Rev 1.4\x00",
		"proc/self/mounts":                     "proc /proc proc rw 0 0\n/dev/mmcblk0p2 / ext4 rw,noatime 0 0\n",
		"sys/class/thermal/thermal_zone0/temp": "47236\n",
		"etc/os-release":                       "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n",
	})

	s := m.Snapshot()

	if s.MemoryTotalBytes != 4000000*1024 || s.MemoryUsedBytes != 1000000*1024 {
		t.Errorf("memory = %d used of %d; cache must count as free", s.MemoryUsedBytes, s.MemoryTotalBytes)
	}
	if s.DiskTotalBytes != 1000*4096 || s.DiskUsedBytes != 600*4096 {
		t.Errorf("disk = %d used of %d; space reserved for root must count as used", s.DiskUsedBytes, s.DiskTotalBytes)
	}
	if s.TemperatureC == nil || math.Abs(*s.TemperatureC-47.236) > 0.0001 {
		t.Errorf("temperature = %v, want 47.236", s.TemperatureC)
	}
	if s.UptimeSeconds != 273845 {
		t.Errorf("uptime = %d", s.UptimeSeconds)
	}
	if s.Kernel != "6.12.47+rpt-rpi-v8" {
		t.Errorf("kernel = %q", s.Kernel)
	}
	if s.Model != "Raspberry Pi 4 Model B Rev 1.4" {
		t.Errorf("model = %q (the trailing NUL must be stripped)", s.Model)
	}
	if s.OS != "Debian GNU/Linux 13 (trixie)" {
		t.Errorf("os = %q", s.OS)
	}
	if s.BootMedium != BootSDCard {
		t.Errorf("boot medium = %q, want %q", s.BootMedium, BootSDCard)
	}
}

func TestMissingSensorsDoNotBreakTheSnapshot(t *testing.T) {
	// A virtual machine: no temperature sensor, no device tree.
	m := newFixture(t, map[string]string{
		"proc/self/mounts":              "/dev/sda1 / ext4 rw 0 0\n",
		"sys/class/dmi/id/product_name": "Virtual Machine\n",
	})

	s := m.Snapshot()

	if s.TemperatureC != nil {
		t.Errorf("temperature = %v, want null when there is no sensor", *s.TemperatureC)
	}
	if s.Model != "Virtual Machine" {
		t.Errorf("model = %q, want the firmware product name", s.Model)
	}
	if s.BootMedium != BootDisk {
		t.Errorf("boot medium = %q, want %q", s.BootMedium, BootDisk)
	}
	if s.MemoryTotalBytes != 0 || s.UptimeSeconds != 0 {
		t.Errorf("unreadable values should be zero, got memory=%d uptime=%d", s.MemoryTotalBytes, s.UptimeSeconds)
	}
}

func TestBootMediumOfUnrecognisedDeviceIsUnknown(t *testing.T) {
	m := newFixture(t, map[string]string{"proc/self/mounts": "overlay / overlay rw 0 0\n"})
	if got := m.Snapshot().BootMedium; got != BootUnknown {
		t.Errorf("boot medium = %q, want %q", got, BootUnknown)
	}
}
