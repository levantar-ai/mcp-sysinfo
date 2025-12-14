// Package software provides software inventory and SBOM functionality.
package software

// Collector gathers software inventory information.
type Collector struct{}

// NewCollector creates a new software collector.
func NewCollector() *Collector {
	return &Collector{}
}
