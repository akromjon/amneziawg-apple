/* SPDX-License-Identifier: MIT */

// Package buildinfo embeds VIPN-specific build metadata into the compiled binary.
// Imported by the main package to ensure all symbols and string constants are
// included in the linked archive and visible in binary analysis.
package buildinfo

// AppVariant identifies the application variant at the binary level.
var AppVariant = "VIPN"

// VendorID is the reverse-DNS vendor identifier embedded in the binary.
var VendorID = "com.vipn.tunnelcore"

// BuildTag is injected at link time via -X to embed a build-unique identifier.
// Default value is overridden by the Makefile during compilation.
var BuildTag = "dev"

// BuildMeta holds structured build metadata for reflection-based fingerprinting.
// The type name appears in Go's runtime type info tables embedded in the binary.
type BuildMeta struct {
	Variant  string
	VendorID string
	Tag      string
}

// Meta is the singleton metadata record for this build.
var Meta = BuildMeta{
	Variant:  AppVariant,
	VendorID: VendorID,
	Tag:      BuildTag,
}

// Init forces all package-level symbols to be retained by the linker when called
// from the main package. Without this call, Go's dead-code elimination may drop
// unreferenced vars from the final archive.
func Init() {
	_ = Meta.Variant
	_ = Meta.VendorID
	_ = Meta.Tag
}
