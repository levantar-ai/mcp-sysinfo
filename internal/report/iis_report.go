// Package report provides IIS report generation with parallel data collection.
package report

import (
	"context"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/collector"
	"github.com/levantar-ai/mcp-sysinfo/internal/windows"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// IISReport contains all IIS-related data for HTML report templates.
type IISReport struct {
	Generated time.Time `json:"generated"`

	// IIS Configuration
	Sites       interface{} `json:"sites,omitempty"`
	AppPools    interface{} `json:"app_pools,omitempty"`
	Bindings    interface{} `json:"bindings,omitempty"`
	VirtualDirs interface{} `json:"virtual_dirs,omitempty"`
	Handlers    interface{} `json:"handlers,omitempty"`
	Modules     interface{} `json:"modules,omitempty"`
	SSLCerts    interface{} `json:"ssl_certs,omitempty"`
	AuthConfig  interface{} `json:"auth_config,omitempty"`

	// Summary Statistics
	Summary *IISSummary `json:"summary,omitempty"`

	// Errors encountered during collection
	Errors map[string]string `json:"errors,omitempty"`
}

// IISSummary provides high-level statistics about IIS configuration.
type IISSummary struct {
	TotalSites      int `json:"total_sites"`
	RunningSites    int `json:"running_sites"`
	StoppedSites    int `json:"stopped_sites"`
	TotalAppPools   int `json:"total_app_pools"`
	RunningAppPools int `json:"running_app_pools"`
	StoppedAppPools int `json:"stopped_app_pools"`
	TotalBindings   int `json:"total_bindings"`
	HTTPSBindings   int `json:"https_bindings"`
	SSLCertificates int `json:"ssl_certificates"`
}

// IISReportGenerator generates IIS reports with parallel collection.
type IISReportGenerator struct {
	timeout time.Duration
}

// NewIISReportGenerator creates a new IIS report generator.
func NewIISReportGenerator(timeout time.Duration) *IISReportGenerator {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &IISReportGenerator{timeout: timeout}
}

// GenerateIISReport collects all IIS data in parallel and returns a report.
func (rg *IISReportGenerator) GenerateIISReport(ctx context.Context, sections []string) (*IISReport, error) {
	pc := collector.NewParallelCollector(rg.timeout)
	wc := windows.NewCollector()

	// Define all IIS collectors
	allCollectors := map[string]collector.CollectorFunc{
		"sites": func(ctx context.Context) (interface{}, error) {
			return wc.GetIISSites()
		},
		"app_pools": func(ctx context.Context) (interface{}, error) {
			return wc.GetIISAppPools()
		},
		"bindings": func(ctx context.Context) (interface{}, error) {
			return wc.GetIISBindings()
		},
		"virtual_dirs": func(ctx context.Context) (interface{}, error) {
			return wc.GetIISVirtualDirs()
		},
		"handlers": func(ctx context.Context) (interface{}, error) {
			return wc.GetIISHandlers()
		},
		"modules": func(ctx context.Context) (interface{}, error) {
			return wc.GetIISModules()
		},
		"ssl_certs": func(ctx context.Context) (interface{}, error) {
			return wc.GetIISSSLCerts()
		},
		"auth_config": func(ctx context.Context) (interface{}, error) {
			return wc.GetIISAuthConfig()
		},
	}

	// Filter collectors if sections specified
	collectors := allCollectors
	if len(sections) > 0 {
		collectors = make(map[string]collector.CollectorFunc)
		for _, s := range sections {
			if fn, ok := allCollectors[s]; ok {
				collectors[s] = fn
			}
		}
	}

	// Run all collectors in parallel
	results := pc.Collect(ctx, collectors)

	// Build report
	report := &IISReport{
		Generated: time.Now().UTC(),
		Errors:    make(map[string]string),
		Summary:   &IISSummary{},
	}

	// Map results to report fields and calculate summary
	for name, result := range results {
		if result.Error != nil {
			report.Errors[name] = result.Error.Error()
			continue
		}

		switch name {
		case "sites":
			report.Sites = result.Data
			// Calculate site statistics
			if sites, ok := result.Data.(*types.IISSitesResult); ok {
				report.Summary.TotalSites = sites.Count
				for _, site := range sites.Sites {
					if site.State == "Started" {
						report.Summary.RunningSites++
					} else {
						report.Summary.StoppedSites++
					}
				}
			}
		case "app_pools":
			report.AppPools = result.Data
			// Calculate app pool statistics
			if pools, ok := result.Data.(*types.IISAppPoolsResult); ok {
				report.Summary.TotalAppPools = pools.Count
				for _, pool := range pools.AppPools {
					if pool.State == "Started" {
						report.Summary.RunningAppPools++
					} else {
						report.Summary.StoppedAppPools++
					}
				}
			}
		case "bindings":
			report.Bindings = result.Data
			// Calculate binding statistics
			if bindings, ok := result.Data.(*types.IISBindingsResult); ok {
				report.Summary.TotalBindings = bindings.Count
				for _, b := range bindings.Bindings {
					if b.Binding.Protocol == "https" {
						report.Summary.HTTPSBindings++
					}
				}
			}
		case "virtual_dirs":
			report.VirtualDirs = result.Data
		case "handlers":
			report.Handlers = result.Data
		case "modules":
			report.Modules = result.Data
		case "ssl_certs":
			report.SSLCerts = result.Data
			// Calculate SSL cert count
			if certs, ok := result.Data.(*types.IISSSLCertsResult); ok {
				report.Summary.SSLCertificates = certs.Count
			}
		case "auth_config":
			report.AuthConfig = result.Data
		}
	}

	return report, nil
}
