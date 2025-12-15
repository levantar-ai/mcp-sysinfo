// Package software provides software inventory and SBOM functionality.
package software

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// GetSBOMCycloneDX generates a CycloneDX 1.4 SBOM from installed packages.
func (c *Collector) GetSBOMCycloneDX() (*types.SBOMResult, error) {
	result := &types.SBOMResult{
		Format:    "CycloneDX",
		Version:   "1.4",
		Timestamp: time.Now(),
	}

	// Collect all packages
	components := c.collectAllComponents()
	result.Components = components
	result.Count = len(components)

	// Generate CycloneDX JSON
	cdx := cycloneDXBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Metadata: cycloneDXMetadata{
			Timestamp: result.Timestamp.Format(time.RFC3339),
			Tools: []cycloneDXTool{{
				Vendor:  "Levantar AI",
				Name:    "mcp-sysinfo",
				Version: "1.0.0",
			}},
		},
		Components: make([]cycloneDXComponent, 0, len(components)),
	}

	for _, comp := range components {
		cdxComp := cycloneDXComponent{
			Type:    comp.Type,
			Name:    comp.Name,
			Version: comp.Version,
			PURL:    comp.PURL,
		}
		if comp.License != "" {
			cdxComp.Licenses = []cycloneDXLicense{{
				License: cycloneDXLicenseID{ID: comp.License},
			}}
		}
		if comp.Description != "" {
			cdxComp.Description = comp.Description
		}
		cdx.Components = append(cdx.Components, cdxComp)
	}

	raw, _ := json.MarshalIndent(cdx, "", "  ")
	result.Raw = string(raw)

	return result, nil
}

// GetSBOMSPDX generates an SPDX 2.3 SBOM from installed packages.
func (c *Collector) GetSBOMSPDX() (*types.SBOMResult, error) {
	result := &types.SBOMResult{
		Format:    "SPDX",
		Version:   "2.3",
		Timestamp: time.Now(),
	}

	// Collect all packages
	components := c.collectAllComponents()
	result.Components = components
	result.Count = len(components)

	// Generate SPDX JSON
	spdx := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "mcp-sysinfo-sbom",
		DocumentNamespace: fmt.Sprintf("https://levantar.ai/spdx/%d", time.Now().Unix()),
		CreationInfo: spdxCreationInfo{
			Created: result.Timestamp.Format(time.RFC3339),
			Creators: []string{
				"Tool: mcp-sysinfo-1.0.0",
			},
		},
		Packages: make([]spdxPackage, 0, len(components)),
	}

	for i, comp := range components {
		pkg := spdxPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             comp.Name,
			VersionInfo:      comp.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		}
		if comp.PURL != "" {
			pkg.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  comp.PURL,
			}}
		}
		if comp.License != "" {
			pkg.LicenseConcluded = comp.License
			pkg.LicenseDeclared = comp.License
		} else {
			pkg.LicenseConcluded = "NOASSERTION"
			pkg.LicenseDeclared = "NOASSERTION"
		}
		pkg.CopyrightText = "NOASSERTION"
		spdx.Packages = append(spdx.Packages, pkg)
	}

	raw, _ := json.MarshalIndent(spdx, "", "  ")
	result.Raw = string(raw)

	return result, nil
}

func (c *Collector) collectAllComponents() []types.SBOMComponent {
	var components []types.SBOMComponent

	// Get system packages
	sysPkgs, _ := c.GetSystemPackages()
	if sysPkgs != nil {
		for _, pkg := range sysPkgs.Packages {
			comp := types.SBOMComponent{
				Type:        "library",
				Name:        pkg.Name,
				Version:     pkg.Version,
				Description: pkg.Description,
				PURL:        generatePURL(sysPkgs.PackageManager, pkg.Name, pkg.Version, pkg.Architecture),
			}
			components = append(components, comp)
		}
	}

	// Get Python packages
	pyPkgs, _ := c.GetPythonPackages()
	if pyPkgs != nil {
		for _, pkg := range pyPkgs.Packages {
			comp := types.SBOMComponent{
				Type:        "library",
				Name:        pkg.Name,
				Version:     pkg.Version,
				Description: pkg.Summary,
				License:     pkg.License,
				PURL:        fmt.Sprintf("pkg:pypi/%s@%s", strings.ToLower(pkg.Name), pkg.Version),
			}
			components = append(components, comp)
		}
	}

	// Get Node packages
	nodePkgs, _ := c.GetNodePackages()
	if nodePkgs != nil {
		for _, pkg := range nodePkgs.Packages {
			comp := types.SBOMComponent{
				Type:        "library",
				Name:        pkg.Name,
				Version:     pkg.Version,
				Description: pkg.Summary,
				License:     pkg.License,
				PURL:        fmt.Sprintf("pkg:npm/%s@%s", pkg.Name, pkg.Version),
			}
			components = append(components, comp)
		}
	}

	// Get Go modules
	goPkgs, _ := c.GetGoModules()
	if goPkgs != nil {
		for _, pkg := range goPkgs.Packages {
			comp := types.SBOMComponent{
				Type:    "library",
				Name:    pkg.Name,
				Version: pkg.Version,
				PURL:    fmt.Sprintf("pkg:golang/%s@%s", pkg.Name, pkg.Version),
			}
			components = append(components, comp)
		}
	}

	// Get Rust crates
	rustPkgs, _ := c.GetRustPackages()
	if rustPkgs != nil {
		for _, pkg := range rustPkgs.Packages {
			comp := types.SBOMComponent{
				Type:    "library",
				Name:    pkg.Name,
				Version: pkg.Version,
				PURL:    fmt.Sprintf("pkg:cargo/%s@%s", pkg.Name, pkg.Version),
			}
			components = append(components, comp)
		}
	}

	// Get Ruby gems
	rubyPkgs, _ := c.GetRubyGems()
	if rubyPkgs != nil {
		for _, pkg := range rubyPkgs.Packages {
			comp := types.SBOMComponent{
				Type:        "library",
				Name:        pkg.Name,
				Version:     pkg.Version,
				Description: pkg.Summary,
				License:     pkg.License,
				PURL:        fmt.Sprintf("pkg:gem/%s@%s", pkg.Name, pkg.Version),
			}
			components = append(components, comp)
		}
	}

	return components
}

func generatePURL(pkgManager, name, version, arch string) string {
	switch pkgManager {
	case "dpkg":
		purl := fmt.Sprintf("pkg:deb/debian/%s@%s", name, version)
		if arch != "" {
			purl += "?arch=" + arch
		}
		return purl
	case "rpm":
		distro := "fedora"
		purl := fmt.Sprintf("pkg:rpm/%s/%s@%s", distro, name, version)
		if arch != "" {
			purl += "?arch=" + arch
		}
		return purl
	case "apk":
		return fmt.Sprintf("pkg:apk/alpine/%s@%s", name, version)
	case "pacman":
		return fmt.Sprintf("pkg:pacman/arch/%s@%s", name, version)
	case "brew", "homebrew":
		return fmt.Sprintf("pkg:brew/%s@%s", name, version)
	case "chocolatey", "choco":
		return fmt.Sprintf("pkg:chocolatey/%s@%s", name, version)
	case "winget":
		return fmt.Sprintf("pkg:winget/%s@%s", name, version)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
}

// CycloneDX types
type cycloneDXBOM struct {
	BOMFormat   string              `json:"bomFormat"`
	SpecVersion string              `json:"specVersion"`
	Version     int                 `json:"version"`
	Metadata    cycloneDXMetadata   `json:"metadata"`
	Components  []cycloneDXComponent `json:"components"`
}

type cycloneDXMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []cycloneDXTool `json:"tools"`
}

type cycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cycloneDXComponent struct {
	Type        string             `json:"type"`
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	PURL        string             `json:"purl,omitempty"`
	Description string             `json:"description,omitempty"`
	Licenses    []cycloneDXLicense `json:"licenses,omitempty"`
}

type cycloneDXLicense struct {
	License cycloneDXLicenseID `json:"license"`
}

type cycloneDXLicenseID struct {
	ID string `json:"id"`
}

// SPDX types
type spdxDocument struct {
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	SPDXID            string           `json:"SPDXID"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo `json:"creationInfo"`
	Packages          []spdxPackage    `json:"packages"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID            string            `json:"SPDXID"`
	Name              string            `json:"name"`
	VersionInfo       string            `json:"versionInfo"`
	DownloadLocation  string            `json:"downloadLocation"`
	FilesAnalyzed     bool              `json:"filesAnalyzed"`
	LicenseConcluded  string            `json:"licenseConcluded"`
	LicenseDeclared   string            `json:"licenseDeclared"`
	CopyrightText     string            `json:"copyrightText"`
	ExternalRefs      []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

