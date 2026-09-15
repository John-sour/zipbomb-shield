package detector

import (
	"archive/zip"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// Config holds detection configuration
type Config struct {
	MaxCompressionRatio float64
	MaxUncompressedSize int64
	MaxNestingDepth     int
	ExtractSample       bool
	Verbose             bool
}

// ZIPAnalyzer performs efficient ZIP analysis
type ZIPAnalyzer struct {
	config *Config
}

// NewZIPAnalyzer creates a new analyzer with config
func NewZIPAnalyzer(config *Config) *ZIPAnalyzer {
	return &ZIPAnalyzer{config: config}
}

// AnalysisResult contains detection results
type AnalysisResult struct {
	FilePath            string
	IsBomb              bool
	CompressionRatio    float64
	TotalUncompressed   int64
	TotalCompressed     int64
	MaxNestingLevel     int
	SuspiciousFiles     []string
	Warnings            []string
	Details             string
}

func (ar *AnalysisResult) String() string {
	s := fmt.Sprintf("ZIP Analysis Report: %s\n", ar.FilePath)
	s += fmt.Sprintf("Status: ")
	if ar.IsBomb {
		s += "🚨 LIKELY ZIPBOMB DETECTED\n"
	} else {
		s += "✓ SAFE\n"
	}
	s += fmt.Sprintf("Compression Ratio: %.2f:1\n", ar.CompressionRatio)
	s += fmt.Sprintf("Compressed Size: %.2f MB\n", float64(ar.TotalCompressed)/1e6)
	s += fmt.Sprintf("Uncompressed Size: %.2f MB\n", float64(ar.TotalUncompressed)/1e6)
	s += fmt.Sprintf("Max Nesting Depth: %d\n", ar.MaxNestingLevel)

	if len(ar.SuspiciousFiles) > 0 {
		s += fmt.Sprintf("\nSuspicious Files (%d):\n", len(ar.SuspiciousFiles))
		for _, f := range ar.SuspiciousFiles {
			s += fmt.Sprintf("  - %s\n", f)
		}
	}

	if len(ar.Warnings) > 0 {
		s += fmt.Sprintf("\nWarnings (%d):\n", len(ar.Warnings))
		for _, w := range ar.Warnings {
			s += fmt.Sprintf("  ⚠ %s\n", w)
		}
	}

	return s
}

// AnalyzeZIP performs comprehensive analysis
func AnalyzeZIP(analyzer *ZIPAnalyzer, filepath string) (*AnalysisResult, error) {
	reader, err := zip.OpenReader(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ZIP: %w", err)
	}
	defer reader.Close()

	result := &AnalysisResult{
		FilePath:        filepath,
		SuspiciousFiles: []string{},
		Warnings:        []string{},
	}

	// Get compressed size
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return nil, err
	}
	result.TotalCompressed = fileInfo.Size()

	// Analyze each file
	var nestingLevels map[string]int = make(map[string]int)

	for _, file := range reader.File {
		// Track uncompressed size
		result.TotalUncompressed += file.UncompressedSize64

		// Check individual file compression ratio
		if file.CompressedSize64 > 0 {
			ratio := float64(file.UncompressedSize64) / float64(file.CompressedSize64)
			if ratio > analyzer.config.MaxCompressionRatio {
				result.SuspiciousFiles = append(result.SuspiciousFiles, file.Name)
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("%s: compression ratio %.2f exceeds threshold", file.Name, ratio))
			}
		}

		// Detect nesting depth
		depth := strings.Count(file.Name, string(filepath.Separator)) + 1
		if depth > result.MaxNestingLevel {
			result.MaxNestingLevel = depth
		}

		// Check for nested archives
		if isArchiveFile(file.Name) && depth > 1 {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("nested archive detected: %s", file.Name))
		}
	}

	// Calculate overall compression ratio
	if result.TotalCompressed > 0 {
		result.CompressionRatio = float64(result.TotalUncompressed) / float64(result.TotalCompressed)
	}

	// Perform threat assessment
	result.IsBomb = assessThreat(result, analyzer.config)

	return result, nil
}

func isArchiveFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	archiveExts := map[string]bool{
		".zip": true,
		".7z":  true,
		".rar": true,
		".tar": true,
		".gz":  true,
	}
	return archiveExts[ext]
}

func assessThreat(result *AnalysisResult, config *Config) bool {
	// Multiple indicators suggest zipbomb
	indicators := 0

	// Indicator 1: Extreme compression ratio
	if result.CompressionRatio > config.MaxCompressionRatio {
		indicators++
	}

	// Indicator 2: Total uncompressed size exceeds threshold
	if result.TotalUncompressed > config.MaxUncompressedSize {
		indicators++
	}

	// Indicator 3: Deep nesting of archives
	if result.MaxNestingLevel > config.MaxNestingDepth {
		indicators++
	}

	// Indicator 4: High number of suspicious files
	if len(result.SuspiciousFiles) > int(result.TotalUncompressed/1e6) {
		indicators++
	}

	return indicators >= 2
}
