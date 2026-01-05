// Package container provides Docker/Podman container inventory functionality.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector gathers container information.
type Collector struct {
	client *http.Client
}

// NewCollector creates a new container collector.
func NewCollector() *Collector {
	return &Collector{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", getDockerSocket())
				},
			},
		},
	}
}

func getDockerSocket() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\docker_engine`
	}
	// Try podman first, then docker
	for _, sock := range []string{
		"/run/user/1000/podman/podman.sock",
		"/run/podman/podman.sock",
		"/var/run/docker.sock",
	} {
		if conn, err := net.Dial("unix", sock); err == nil {
			_ = conn.Close() // #nosec G104 -- best effort close
			return sock
		}
	}
	return "/var/run/docker.sock"
}

// GetDockerImages returns list of Docker/Podman images.
func (c *Collector) GetDockerImages() (*types.ContainerImagesResult, error) {
	result := &types.ContainerImagesResult{
		Images:    []types.ContainerImage{},
		Timestamp: time.Now(),
	}

	resp, err := c.doRequest("GET", "/images/json")
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Sprintf("Docker API error: %s", string(body))
		return result, nil
	}

	var images []dockerImage
	if err := json.NewDecoder(resp.Body).Decode(&images); err != nil {
		result.Error = fmt.Sprintf("Failed to parse response: %v", err)
		return result, nil
	}

	for _, img := range images {
		image := types.ContainerImage{
			ID:      shortenID(img.ID),
			Created: time.Unix(img.Created, 0),
			Size:    img.Size,
			Labels:  img.Labels,
		}

		// Extract repo tags
		if len(img.RepoTags) > 0 {
			for _, tag := range img.RepoTags {
				if tag != "<none>:<none>" {
					parts := strings.Split(tag, ":")
					if len(parts) == 2 {
						image.Repository = parts[0]
						image.Tag = parts[1]
					} else {
						image.Repository = tag
					}
					break
				}
			}
			image.Tags = img.RepoTags
		}

		if len(img.RepoDigests) > 0 {
			image.Digests = img.RepoDigests
		}

		result.Images = append(result.Images, image)
	}

	result.Count = len(result.Images)
	return result, nil
}

// GetDockerContainers returns list of Docker/Podman containers.
func (c *Collector) GetDockerContainers() (*types.DockerContainersResult, error) {
	result := &types.DockerContainersResult{
		Containers: []types.DockerContainer{},
		Timestamp:  time.Now(),
	}

	resp, err := c.doRequest("GET", "/containers/json?all=true")
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Sprintf("Docker API error: %s", string(body))
		return result, nil
	}

	var containers []dockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		result.Error = fmt.Sprintf("Failed to parse response: %v", err)
		return result, nil
	}

	for _, ctr := range containers {
		container := types.DockerContainer{
			ID:      shortenID(ctr.ID),
			Image:   ctr.Image,
			ImageID: shortenID(ctr.ImageID),
			Command: ctr.Command,
			Created: time.Unix(ctr.Created, 0),
			State:   ctr.State,
			Status:  ctr.Status,
			Labels:  ctr.Labels,
		}

		if len(ctr.Names) > 0 {
			container.Name = strings.TrimPrefix(ctr.Names[0], "/")
			container.Names = ctr.Names
		}

		// Parse ports
		for _, p := range ctr.Ports {
			port := types.DockerPort{
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
				IP:          p.IP,
			}
			container.Ports = append(container.Ports, port)
		}

		result.Containers = append(result.Containers, container)

		// Count by state
		switch ctr.State {
		case "running":
			result.Running++
		case "paused":
			result.Paused++
		case "exited", "dead":
			result.Stopped++
		}
	}

	result.Count = len(result.Containers)
	return result, nil
}

// GetImageHistory returns the history/layers of a Docker image.
func (c *Collector) GetImageHistory(imageID string) (*types.ImageHistoryResult, error) {
	result := &types.ImageHistoryResult{
		ImageID:   imageID,
		Layers:    []types.ImageLayer{},
		Timestamp: time.Now(),
	}

	if imageID == "" {
		result.Error = "image ID is required"
		return result, nil
	}

	resp, err := c.doRequest("GET", fmt.Sprintf("/images/%s/history", imageID))
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Sprintf("Docker API error: %s", string(body))
		return result, nil
	}

	var layers []dockerHistoryLayer
	if err := json.NewDecoder(resp.Body).Decode(&layers); err != nil {
		result.Error = fmt.Sprintf("Failed to parse response: %v", err)
		return result, nil
	}

	for _, layer := range layers {
		l := types.ImageLayer{
			ID:        shortenID(layer.ID),
			Created:   time.Unix(layer.Created, 0),
			CreatedBy: layer.CreatedBy,
			Size:      layer.Size,
			Comment:   layer.Comment,
		}

		if len(layer.Tags) > 0 {
			l.Tags = layer.Tags
		}

		result.Layers = append(result.Layers, l)
		result.TotalSize += layer.Size
	}

	result.LayerCount = len(result.Layers)
	return result, nil
}

func (c *Collector) doRequest(method, path string) (*http.Response, error) {
	req, err := http.NewRequest(method, "http://localhost"+path, nil)
	if err != nil {
		return nil, err
	}
	return c.client.Do(req)
}

func shortenID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Docker API response types
type dockerImage struct {
	ID          string            `json:"Id"`
	RepoTags    []string          `json:"RepoTags"`
	RepoDigests []string          `json:"RepoDigests"`
	Created     int64             `json:"Created"`
	Size        int64             `json:"Size"`
	Labels      map[string]string `json:"Labels"`
}

type dockerContainer struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	ImageID string   `json:"ImageID"`
	Command string   `json:"Command"`
	Created int64    `json:"Created"`
	State   string   `json:"State"`
	Status  string   `json:"Status"`
	Ports   []struct {
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
		IP          string `json:"IP"`
	} `json:"Ports"`
	Labels map[string]string `json:"Labels"`
}

type dockerHistoryLayer struct {
	ID        string   `json:"Id"`
	Created   int64    `json:"Created"`
	CreatedBy string   `json:"CreatedBy"`
	Tags      []string `json:"Tags"`
	Size      int64    `json:"Size"`
	Comment   string   `json:"Comment"`
}

// GetContainerStats returns real-time stats for running containers.
func (c *Collector) GetContainerStats(containerID string) (*types.ContainerStatsResult, error) {
	result := &types.ContainerStatsResult{
		Stats:     []types.ContainerStats{},
		Timestamp: time.Now(),
	}

	// If a specific container is requested, get stats for that container
	if containerID != "" {
		stats, err := c.getContainerStats(containerID)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Stats = append(result.Stats, *stats)
		result.Count = 1
		return result, nil
	}

	// Otherwise, get stats for all running containers
	containers, err := c.GetDockerContainers()
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	for _, ctr := range containers.Containers {
		if ctr.State != "running" {
			continue
		}
		stats, err := c.getContainerStats(ctr.ID)
		if err != nil {
			continue // Skip containers we can't get stats for
		}
		stats.Name = ctr.Name
		result.Stats = append(result.Stats, *stats)
	}

	result.Count = len(result.Stats)
	return result, nil
}

func (c *Collector) getContainerStats(containerID string) (*types.ContainerStats, error) {
	resp, err := c.doRequest("GET", fmt.Sprintf("/containers/%s/stats?stream=false", containerID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Docker API error: %s", string(body))
	}

	var dockerStats dockerStatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&dockerStats); err != nil {
		return nil, fmt.Errorf("failed to parse stats: %v", err)
	}

	stats := &types.ContainerStats{
		ID:       shortenID(containerID),
		ReadTime: dockerStats.Read,
	}

	// Calculate CPU percentage
	cpuDelta := float64(dockerStats.CPUStats.CPUUsage.TotalUsage - dockerStats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(dockerStats.CPUStats.SystemCPUUsage - dockerStats.PreCPUStats.SystemCPUUsage)
	if systemDelta > 0 && cpuDelta > 0 {
		numCPUs := float64(dockerStats.CPUStats.OnlineCPUs)
		if numCPUs == 0 {
			numCPUs = float64(len(dockerStats.CPUStats.CPUUsage.PercpuUsage))
		}
		if numCPUs == 0 {
			numCPUs = 1
		}
		stats.CPUPercent = (cpuDelta / systemDelta) * numCPUs * 100.0
	}

	stats.CPUSystemNanos = dockerStats.CPUStats.SystemCPUUsage
	stats.CPUUserNanos = dockerStats.CPUStats.CPUUsage.UsageInUsermode

	// Memory stats
	stats.MemoryUsage = dockerStats.MemoryStats.Usage
	stats.MemoryLimit = dockerStats.MemoryStats.Limit
	if stats.MemoryLimit > 0 {
		stats.MemoryPercent = float64(stats.MemoryUsage) / float64(stats.MemoryLimit) * 100
	}
	stats.MemoryCache = dockerStats.MemoryStats.Stats.Cache

	// Network stats - aggregate all interfaces
	for _, netStats := range dockerStats.Networks {
		stats.NetworkRxBytes += netStats.RxBytes
		stats.NetworkTxBytes += netStats.TxBytes
		stats.NetworkRxPackets += netStats.RxPackets
		stats.NetworkTxPackets += netStats.TxPackets
	}

	// Block I/O stats
	for _, entry := range dockerStats.BlkioStats.IOServiceBytesRecursive {
		switch entry.Op {
		case "Read":
			stats.BlockReadBytes += entry.Value
		case "Write":
			stats.BlockWriteBytes += entry.Value
		}
	}

	// PIDs
	stats.PIDs = dockerStats.PidsStats.Current

	return stats, nil
}

// GetContainerLogs returns logs from a container.
func (c *Collector) GetContainerLogs(containerID string, lines int, since string) (*types.ContainerLogsResult, error) {
	result := &types.ContainerLogsResult{
		ContainerID: containerID,
		Logs:        []types.ContainerLog{},
		Timestamp:   time.Now(),
	}

	if containerID == "" {
		result.Error = "container ID is required"
		return result, nil
	}

	// Build query parameters
	query := fmt.Sprintf("/containers/%s/logs?stdout=true&stderr=true&timestamps=true", containerID)
	if lines > 0 {
		query += fmt.Sprintf("&tail=%d", lines)
	} else {
		query += "&tail=100" // Default to last 100 lines
	}
	if since != "" {
		query += fmt.Sprintf("&since=%s", since)
	}

	resp, err := c.doRequest("GET", query)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		result.Error = fmt.Sprintf("Docker API error: %s", string(body))
		return result, nil
	}

	// Docker log format: first 8 bytes are header (1 byte stream type, 3 bytes padding, 4 bytes size)
	// Stream type: 0=stdin, 1=stdout, 2=stderr
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read logs: %v", err)
		return result, nil
	}

	// Parse multiplexed output
	result.Logs = parseDockerLogs(body)
	result.Count = len(result.Logs)

	// Get container name
	containers, err := c.GetDockerContainers()
	if err == nil {
		for _, ctr := range containers.Containers {
			if strings.HasPrefix(containerID, ctr.ID) || ctr.ID == containerID {
				result.Name = ctr.Name
				break
			}
		}
	}

	return result, nil
}

func parseDockerLogs(data []byte) []types.ContainerLog {
	var logs []types.ContainerLog

	i := 0
	for i < len(data) {
		// Need at least 8 bytes for header
		if i+8 > len(data) {
			break
		}

		// First byte is stream type
		streamType := data[i]
		stream := "stdout"
		if streamType == 2 {
			stream = "stderr"
		}

		// Bytes 4-7 are the size (big endian)
		size := int(data[i+4])<<24 | int(data[i+5])<<16 | int(data[i+6])<<8 | int(data[i+7])

		// Skip header
		i += 8

		// Read the message
		if i+size > len(data) {
			size = len(data) - i
		}

		message := string(data[i : i+size])
		i += size

		// Parse timestamp from message (format: 2024-01-15T10:30:00.123456789Z message)
		var timestamp time.Time
		if len(message) > 30 && message[4] == '-' && message[7] == '-' {
			// Find the space after timestamp
			spaceIdx := strings.Index(message, " ")
			if spaceIdx > 0 {
				tsStr := message[:spaceIdx]
				if ts, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
					timestamp = ts
					message = message[spaceIdx+1:]
				}
			}
		}

		logs = append(logs, types.ContainerLog{
			Timestamp: timestamp,
			Stream:    stream,
			Message:   strings.TrimRight(message, "\n"),
		})
	}

	return logs
}

// Docker stats API response structures
type dockerStatsResponse struct {
	Read     time.Time `json:"read"`
	PreRead  time.Time `json:"preread"`
	CPUStats struct {
		CPUUsage struct {
			TotalUsage        uint64   `json:"total_usage"`
			PercpuUsage       []uint64 `json:"percpu_usage"`
			UsageInKernelmode uint64   `json:"usage_in_kernelmode"`
			UsageInUsermode   uint64   `json:"usage_in_usermode"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs     int    `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage        uint64   `json:"total_usage"`
			PercpuUsage       []uint64 `json:"percpu_usage"`
			UsageInKernelmode uint64   `json:"usage_in_kernelmode"`
			UsageInUsermode   uint64   `json:"usage_in_usermode"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs     int    `json:"online_cpus"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
		Stats struct {
			Cache uint64 `json:"cache"`
		} `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes   uint64 `json:"rx_bytes"`
		TxBytes   uint64 `json:"tx_bytes"`
		RxPackets uint64 `json:"rx_packets"`
		TxPackets uint64 `json:"tx_packets"`
	} `json:"networks"`
	BlkioStats struct {
		IOServiceBytesRecursive []struct {
			Op    string `json:"op"`
			Value uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
	PidsStats struct {
		Current int `json:"current"`
	} `json:"pids_stats"`
}
