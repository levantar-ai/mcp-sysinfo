//go:build linux

package resources

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getProcessEnviron reads environment variables from /proc/[pid]/environ.
func (c *Collector) getProcessEnviron(pid int32) (*types.ProcessEnvironResult, error) {
	result := &types.ProcessEnvironResult{
		PID:       pid,
		Environ:   make(map[string]string),
		Timestamp: time.Now(),
	}

	// Read process name
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	// #nosec G304 -- reading from procfs
	if data, err := os.ReadFile(commPath); err == nil {
		result.Name = strings.TrimSpace(string(data))
	}

	// Read environ (null-separated key=value pairs)
	environPath := fmt.Sprintf("/proc/%d/environ", pid)
	// #nosec G304 -- reading from procfs
	data, err := os.ReadFile(environPath)
	if err != nil {
		return nil, fmt.Errorf("reading environ: %w", err)
	}

	// Parse null-separated entries
	entries := strings.Split(string(data), "\x00")
	for _, entry := range entries {
		if entry == "" {
			continue
		}
		if idx := strings.Index(entry, "="); idx > 0 {
			key := entry[:idx]
			value := entry[idx+1:]
			result.Environ[key] = value
		}
	}

	return result, nil
}

// getIPCResources reads System V IPC resources from /proc/sysvipc/*.
func (c *Collector) getIPCResources() (*types.IPCResourcesResult, error) {
	result := &types.IPCResourcesResult{
		Timestamp: time.Now(),
	}

	// Read shared memory segments from /proc/sysvipc/shm
	result.SharedMemory = c.readSharedMemory()

	// Read semaphores from /proc/sysvipc/sem
	result.Semaphores = c.readSemaphores()

	// Read message queues from /proc/sysvipc/msg
	result.MessageQueues = c.readMessageQueues()

	return result, nil
}

// readSharedMemory reads shared memory segments from /proc/sysvipc/shm.
func (c *Collector) readSharedMemory() []types.SharedMemorySegment {
	var segments []types.SharedMemorySegment

	// #nosec G304 -- reading from procfs
	file, err := os.Open("/proc/sysvipc/shm")
	if err != nil {
		return segments
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	_ = scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}

		seg := types.SharedMemorySegment{}

		// Parse fields: key shmid perms size cpid lpid nattch uid gid cuid cgid atime dtime ctime
		if key, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			seg.Key = fmt.Sprintf("0x%08x", key)
		}
		if id, err := strconv.Atoi(fields[1]); err == nil {
			seg.ID = id
		}
		if perms, err := strconv.ParseUint(fields[2], 8, 32); err == nil {
			seg.Permissions = fmt.Sprintf("%04o", perms)
		}
		if size, err := strconv.ParseUint(fields[3], 10, 64); err == nil {
			seg.Bytes = size
		}
		if nattch, err := strconv.Atoi(fields[6]); err == nil {
			seg.AttachCount = nattch
		}
		// Get owner from UID
		if uid, err := strconv.Atoi(fields[7]); err == nil {
			seg.Owner = fmt.Sprintf("%d", uid)
		}

		segments = append(segments, seg)
	}

	return segments
}

// readSemaphores reads semaphore sets from /proc/sysvipc/sem.
func (c *Collector) readSemaphores() []types.SemaphoreSet {
	var semSets []types.SemaphoreSet

	// #nosec G304 -- reading from procfs
	file, err := os.Open("/proc/sysvipc/sem")
	if err != nil {
		return semSets
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	_ = scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		sem := types.SemaphoreSet{}

		// Parse fields: key semid perms nsems uid gid cuid cgid otime ctime
		if key, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			sem.Key = fmt.Sprintf("0x%08x", key)
		}
		if id, err := strconv.Atoi(fields[1]); err == nil {
			sem.ID = id
		}
		if perms, err := strconv.ParseUint(fields[2], 8, 32); err == nil {
			sem.Permissions = fmt.Sprintf("%04o", perms)
		}
		if nsems, err := strconv.Atoi(fields[3]); err == nil {
			sem.NumSems = nsems
		}
		if uid, err := strconv.Atoi(fields[4]); err == nil {
			sem.Owner = fmt.Sprintf("%d", uid)
		}

		semSets = append(semSets, sem)
	}

	return semSets
}

// readMessageQueues reads message queues from /proc/sysvipc/msg.
func (c *Collector) readMessageQueues() []types.MessageQueue {
	var queues []types.MessageQueue

	// #nosec G304 -- reading from procfs
	file, err := os.Open("/proc/sysvipc/msg")
	if err != nil {
		return queues
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	_ = scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}

		mq := types.MessageQueue{}

		// Parse fields: key msqid perms cbytes qnum lspid lrpid uid gid cuid cgid stime rtime ctime
		if key, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			mq.Key = fmt.Sprintf("0x%08x", key)
		}
		if id, err := strconv.Atoi(fields[1]); err == nil {
			mq.ID = id
		}
		if perms, err := strconv.ParseUint(fields[2], 8, 32); err == nil {
			mq.Permissions = fmt.Sprintf("%04o", perms)
		}
		if cbytes, err := strconv.ParseUint(fields[3], 10, 64); err == nil {
			mq.Bytes = cbytes
		}
		if qnum, err := strconv.Atoi(fields[4]); err == nil {
			mq.Messages = qnum
		}
		if uid, err := strconv.Atoi(fields[7]); err == nil {
			mq.Owner = fmt.Sprintf("%d", uid)
		}

		queues = append(queues, mq)
	}

	return queues
}

// getNamespaces reads namespace information from /proc/[pid]/ns/.
func (c *Collector) getNamespaces() (*types.NamespacesResult, error) {
	var namespaces []types.Namespace

	// Read all processes and their namespaces
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("reading proc: %w", err)
	}

	// Track unique namespace IDs
	seenNS := make(map[uint64]bool)

	nsTypes := []string{"mnt", "uts", "ipc", "pid", "net", "user", "cgroup"}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		nsDir := filepath.Join(procDir, entry.Name(), "ns")
		for _, nsType := range nsTypes {
			nsPath := filepath.Join(nsDir, nsType)
			target, err := os.Readlink(nsPath)
			if err != nil {
				continue
			}

			// Parse namespace ID from target (e.g., "net:[4026531993]")
			var nsID uint64
			if idx := strings.Index(target, "["); idx >= 0 {
				idStr := strings.Trim(target[idx:], "[]")
				nsID, _ = strconv.ParseUint(idStr, 10, 64)
			}

			if nsID == 0 || seenNS[nsID] {
				continue
			}
			seenNS[nsID] = true

			ns := types.Namespace{
				Type:   nsType,
				ID:     nsID,
				PID:    int32(pid),
				NSPath: nsPath,
			}

			// Get process command
			commPath := filepath.Join(procDir, entry.Name(), "comm")
			// #nosec G304 -- reading from procfs
			if data, err := os.ReadFile(commPath); err == nil {
				ns.Command = strings.TrimSpace(string(data))
			}

			namespaces = append(namespaces, ns)
		}
	}

	return &types.NamespacesResult{
		Namespaces: namespaces,
		Count:      len(namespaces),
		Timestamp:  time.Now(),
	}, nil
}

// getCgroups reads cgroup information from /sys/fs/cgroup/.
func (c *Collector) getCgroups() (*types.CgroupsResult, error) {
	result := &types.CgroupsResult{
		Timestamp: time.Now(),
	}

	// Detect cgroup version
	cgroupPath := "/sys/fs/cgroup"
	controllersPath := filepath.Join(cgroupPath, "cgroup.controllers")

	// #nosec G304 -- reading from sysfs
	if _, err := os.Stat(controllersPath); err == nil {
		// cgroup v2 (unified hierarchy)
		result.Version = 2
		result.Groups = c.readCgroupV2(cgroupPath)
	} else {
		// cgroup v1 (legacy hierarchy)
		result.Version = 1
		result.Groups = c.readCgroupV1(cgroupPath)
	}

	return result, nil
}

// readCgroupV2 reads cgroup v2 (unified hierarchy) information.
func (c *Collector) readCgroupV2(basePath string) []types.CgroupInfo {
	var groups []types.CgroupInfo

	// Read root cgroup
	root := types.CgroupInfo{
		Name:   "/",
		Path:   basePath,
		Limits: make(map[string]string),
		Usage:  make(map[string]string),
	}

	// Read controllers
	// #nosec G304 -- reading from sysfs
	if data, err := os.ReadFile(filepath.Join(basePath, "cgroup.controllers")); err == nil {
		root.Limits["controllers"] = strings.TrimSpace(string(data))
	}

	// Read memory limits and usage
	// #nosec G304 -- reading from sysfs
	if data, err := os.ReadFile(filepath.Join(basePath, "memory.max")); err == nil {
		root.Limits["memory.max"] = strings.TrimSpace(string(data))
	}
	// #nosec G304 -- reading from sysfs
	if data, err := os.ReadFile(filepath.Join(basePath, "memory.current")); err == nil {
		root.Usage["memory.current"] = strings.TrimSpace(string(data))
	}

	// Read CPU limits
	// #nosec G304 -- reading from sysfs
	if data, err := os.ReadFile(filepath.Join(basePath, "cpu.max")); err == nil {
		root.Limits["cpu.max"] = strings.TrimSpace(string(data))
	}

	groups = append(groups, root)

	// Scan for child cgroups
	entries, _ := os.ReadDir(basePath)
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), "cgroup.") {
			continue
		}

		childPath := filepath.Join(basePath, entry.Name())
		child := types.CgroupInfo{
			Name:   "/" + entry.Name(),
			Path:   childPath,
			Limits: make(map[string]string),
			Usage:  make(map[string]string),
		}

		// Read child cgroup info
		// #nosec G304 -- reading from sysfs
		if data, err := os.ReadFile(filepath.Join(childPath, "memory.max")); err == nil {
			child.Limits["memory.max"] = strings.TrimSpace(string(data))
		}
		// #nosec G304 -- reading from sysfs
		if data, err := os.ReadFile(filepath.Join(childPath, "memory.current")); err == nil {
			child.Usage["memory.current"] = strings.TrimSpace(string(data))
		}

		groups = append(groups, child)
	}

	return groups
}

// readCgroupV1 reads cgroup v1 (legacy hierarchy) information.
func (c *Collector) readCgroupV1(basePath string) []types.CgroupInfo {
	var groups []types.CgroupInfo

	// Scan for controller directories
	entries, _ := os.ReadDir(basePath)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		controllerPath := filepath.Join(basePath, entry.Name())
		group := types.CgroupInfo{
			Name:       "/" + entry.Name(),
			Path:       controllerPath,
			Controller: entry.Name(),
			Limits:     make(map[string]string),
			Usage:      make(map[string]string),
		}

		// Read common limit files based on controller type
		switch entry.Name() {
		case "memory":
			// #nosec G304 -- reading from sysfs
			if data, err := os.ReadFile(filepath.Join(controllerPath, "memory.limit_in_bytes")); err == nil {
				group.Limits["limit_in_bytes"] = strings.TrimSpace(string(data))
			}
			// #nosec G304 -- reading from sysfs
			if data, err := os.ReadFile(filepath.Join(controllerPath, "memory.usage_in_bytes")); err == nil {
				group.Usage["usage_in_bytes"] = strings.TrimSpace(string(data))
			}
		case "cpu":
			// #nosec G304 -- reading from sysfs
			if data, err := os.ReadFile(filepath.Join(controllerPath, "cpu.cfs_quota_us")); err == nil {
				group.Limits["cfs_quota_us"] = strings.TrimSpace(string(data))
			}
			// #nosec G304 -- reading from sysfs
			if data, err := os.ReadFile(filepath.Join(controllerPath, "cpu.cfs_period_us")); err == nil {
				group.Limits["cfs_period_us"] = strings.TrimSpace(string(data))
			}
		case "cpuset":
			// #nosec G304 -- reading from sysfs
			if data, err := os.ReadFile(filepath.Join(controllerPath, "cpuset.cpus")); err == nil {
				group.Limits["cpus"] = strings.TrimSpace(string(data))
			}
			// #nosec G304 -- reading from sysfs
			if data, err := os.ReadFile(filepath.Join(controllerPath, "cpuset.mems")); err == nil {
				group.Limits["mems"] = strings.TrimSpace(string(data))
			}
		}

		groups = append(groups, group)
	}

	return groups
}

// getCapabilities reads process capabilities from /proc/[pid]/status.
func (c *Collector) getCapabilities(pid int32) (*types.CapabilitiesResult, error) {
	result := &types.CapabilitiesResult{
		PID:       pid,
		Timestamp: time.Now(),
	}

	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	// #nosec G304 -- reading from procfs
	file, err := os.Open(statusPath)
	if err != nil {
		return nil, fmt.Errorf("opening status: %w", err)
	}
	defer file.Close()

	var capEff, capPrm, capInh, capBnd, capAmb uint64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			result.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "CapEff:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			capEff, _ = strconv.ParseUint(val, 16, 64)
		} else if strings.HasPrefix(line, "CapPrm:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
			capPrm, _ = strconv.ParseUint(val, 16, 64)
		} else if strings.HasPrefix(line, "CapInh:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "CapInh:"))
			capInh, _ = strconv.ParseUint(val, 16, 64)
		} else if strings.HasPrefix(line, "CapBnd:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "CapBnd:"))
			capBnd, _ = strconv.ParseUint(val, 16, 64)
		} else if strings.HasPrefix(line, "CapAmb:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "CapAmb:"))
			capAmb, _ = strconv.ParseUint(val, 16, 64)
		}
	}

	// Convert bitmasks to capability names
	result.Effective = capBitmaskToNames(capEff)
	result.Permitted = capBitmaskToNames(capPrm)
	result.Inheritable = capBitmaskToNames(capInh)
	result.Bounding = capBitmaskToNames(capBnd)
	result.Ambient = capBitmaskToNames(capAmb)

	return result, nil
}

// capBitmaskToNames converts a capability bitmask to a list of capability names.
func capBitmaskToNames(mask uint64) []string {
	var names []string

	// Linux capability names (see include/uapi/linux/capability.h)
	capNames := []string{
		"CAP_CHOWN",            // 0
		"CAP_DAC_OVERRIDE",     // 1
		"CAP_DAC_READ_SEARCH",  // 2
		"CAP_FOWNER",           // 3
		"CAP_FSETID",           // 4
		"CAP_KILL",             // 5
		"CAP_SETGID",           // 6
		"CAP_SETUID",           // 7
		"CAP_SETPCAP",          // 8
		"CAP_LINUX_IMMUTABLE",  // 9
		"CAP_NET_BIND_SERVICE", // 10
		"CAP_NET_BROADCAST",    // 11
		"CAP_NET_ADMIN",        // 12
		"CAP_NET_RAW",          // 13
		"CAP_IPC_LOCK",         // 14
		"CAP_IPC_OWNER",        // 15
		"CAP_SYS_MODULE",       // 16
		"CAP_SYS_RAWIO",        // 17
		"CAP_SYS_CHROOT",       // 18
		"CAP_SYS_PTRACE",       // 19
		"CAP_SYS_PACCT",        // 20
		"CAP_SYS_ADMIN",        // 21
		"CAP_SYS_BOOT",         // 22
		"CAP_SYS_NICE",         // 23
		"CAP_SYS_RESOURCE",     // 24
		"CAP_SYS_TIME",         // 25
		"CAP_SYS_TTY_CONFIG",   // 26
		"CAP_MKNOD",            // 27
		"CAP_LEASE",            // 28
		"CAP_AUDIT_WRITE",      // 29
		"CAP_AUDIT_CONTROL",    // 30
		"CAP_SETFCAP",          // 31
		"CAP_MAC_OVERRIDE",     // 32
		"CAP_MAC_ADMIN",        // 33
		"CAP_SYSLOG",           // 34
		"CAP_WAKE_ALARM",       // 35
		"CAP_BLOCK_SUSPEND",    // 36
		"CAP_AUDIT_READ",       // 37
		"CAP_PERFMON",          // 38
		"CAP_BPF",              // 39
		"CAP_CHECKPOINT_RESTORE", // 40
	}

	for i, name := range capNames {
		if mask&(1<<i) != 0 {
			names = append(names, name)
		}
	}

	return names
}
