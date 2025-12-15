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
			conn.Close()
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
