package detector

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ArchiveType represents supported archive formats
type ArchiveType int

const (
	ArchiveTypeZIP ArchiveType = iota
	ArchiveType7Z
	ArchiveTypeRAR
	ArchiveTypeTAR
	ArchiveTypeTARGZ
	ArchiveTypeUnknown
)

// DetectArchiveType identifies the archive format
func DetectArchiveType(filepath string) ArchiveType {
	ext := strings.ToLower(filepath)

	if strings.HasSuffix(ext, ".zip") {
		return ArchiveTypeZIP
	}
	if strings.HasSuffix(ext, ".7z") {
		return ArchiveType7Z
	}
	if strings.HasSuffix(ext, ".rar") {
		return ArchiveTypeRAR
	}
	if strings.HasSuffix(ext, ".tar.gz") || strings.HasSuffix(ext, ".tgz") {
		return ArchiveTypeTARGZ
	}
	if strings.HasSuffix(ext, ".tar") {
		return ArchiveTypeTAR
	}

	return ArchiveTypeUnknown
}

// AnalyzeTARGZ analyzes TAR.GZ archives
func AnalyzeTARGZ(config *Config, filepath string) (*ArchiveAnalysis, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip header: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	analysis := &ArchiveAnalysis{
		FilePath:        filepath,
		Type:            ArchiveTypeTARGZ,
		SuspiciousFiles: []string{},
		Warnings:        []string{},
	}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar: %w", err)
		}

		if header.Size > config.MaxUncompressedSize {
			analysis.SuspiciousFiles = append(analysis.SuspiciousFiles, header.Name)
			analysis.Warnings = append(analysis.Warnings,
				fmt.Sprintf("%s: size %d exceeds limit", header.Name, header.Size))
		}

		analysis.TotalUncompressed += header.Size
		if analysis.TotalUncompressed > config.MaxUncompressedSize {
			analysis.IsBomb = true
			analysis.Warnings = append(analysis.Warnings,
				fmt.Sprintf("total uncompressed size exceeds limit"))
			break
		}
	}

	fileInfo, _ := os.Stat(filepath)
	analysis.TotalCompressed = fileInfo.Size()

	if analysis.TotalCompressed > 0 {
		analysis.CompressionRatio = float64(analysis.TotalUncompressed) / float64(analysis.TotalCompressed)
	}

	if analysis.CompressionRatio > config.MaxCompressionRatio {
		analysis.IsBomb = true
	}

	return analysis, nil
}

// AnalyzeTAR analyzes TAR archives
func AnalyzeTAR(config *Config, filepath string) (*ArchiveAnalysis, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	tarReader := tar.NewReader(file)

	analysis := &ArchiveAnalysis{
		FilePath:        filepath,
		Type:            ArchiveTypeTAR,
		SuspiciousFiles: []string{},
		Warnings:        []string{},
	}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar: %w", err)
		}

		if header.Size > config.MaxUncompressedSize {
			analysis.SuspiciousFiles = append(analysis.SuspiciousFiles, header.Name)
		}

		analysis.TotalUncompressed += header.Size
	}

	fileInfo, _ := os.Stat(filepath)
	analysis.TotalCompressed = fileInfo.Size()

	if analysis.TotalCompressed > 0 {
		analysis.CompressionRatio = float64(analysis.TotalUncompressed) / float64(analysis.TotalCompressed)
	}

	if analysis.CompressionRatio > config.MaxCompressionRatio || analysis.TotalUncompressed > config.MaxUncompressedSize {
		analysis.IsBomb = true
	}

	return analysis, nil
}

// Stub implementations for 7Z and RAR (require external libraries)
// These would need: github.com/bodgit/sevenzip and github.com/nwaples/rardecode

// Analyze7Z analyzes 7Z archives (requires external library)
func Analyze7Z(config *Config, filepath string) (*ArchiveAnalysis, error) {
	return nil, fmt.Errorf("7Z support requires: go get github.com/bodgit/sevenzip")
}

// AnalyzeRAR analyzes RAR archives (requires external library)
func AnalyzeRAR(config *Config, filepath string) (*ArchiveAnalysis, error) {
	return nil, fmt.Errorf("RAR support requires: go get github.com/nwaples/rardecode")
}

// ArchiveAnalysis holds multi-format analysis results
type ArchiveAnalysis struct {
	FilePath            string
	Type                ArchiveType
	IsBomb              bool
	CompressionRatio    float64
	TotalUncompressed   int64
	TotalCompressed     int64
	MaxNestingLevel     int
	SuspiciousFiles     []string
	Warnings            []string
}

func (aa *ArchiveAnalysis) String() string {
	typeStr := "Unknown"
	switch aa.Type {
	case ArchiveTypeZIP:
		typeStr = "ZIP"
	case ArchiveType7Z:
		typeStr = "7Z"
	case ArchiveTypeRAR:
		typeStr = "RAR"
	case ArchiveTypeTAR:
		typeStr = "TAR"
	case ArchiveTypeTARGZ:
		typeStr = "TAR.GZ"
	}

	s := fmt.Sprintf("Archive Analysis Report: %s\n", aa.FilePath)
	s += fmt.Sprintf("Format: %s\n", typeStr)
	s += fmt.Sprintf("Status: ")
	if aa.IsBomb {
		s += "🚨 LIKELY ZIPBOMB DETECTED\n"
	} else {
		s += "✓ SAFE\n"
	}
	s += fmt.Sprintf("Compression Ratio: %.2f:1\n", aa.CompressionRatio)
	s += fmt.Sprintf("Compressed Size: %.2f MB\n", float64(aa.TotalCompressed)/1e6)
	s += fmt.Sprintf("Uncompressed Size: %.2f MB\n", float64(aa.TotalUncompressed)/1e6)

	if len(aa.SuspiciousFiles) > 0 {
		s += fmt.Sprintf("\nSuspicious Files (%d):\n", len(aa.SuspiciousFiles))
		for _, f := range aa.SuspiciousFiles {
			s += fmt.Sprintf("  - %s\n", f)
		}
	}

	if len(aa.Warnings) > 0 {
		s += fmt.Sprintf("\nWarnings (%d):\n", len(aa.Warnings))
		for _, w := range aa.Warnings {
			s += fmt.Sprintf("  ⚠ %s\n", w)
		}
	}

	return s
}
