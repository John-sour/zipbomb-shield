package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/John-sour/zipbomb-shield/detector"
)

func main() {
	var (
		filePath      = flag.String("file", "", "Path to ZIP file to analyze")
		maxRatio      = flag.Float64("ratio", 100.0, "Maximum allowed compression ratio (compressed:uncompressed)")
		maxSize       = flag.Int64("max-size", 1e9, "Maximum allowed uncompressed size in bytes (default 1GB)")
		maxDepth      = flag.Int("max-depth", 3, "Maximum nesting depth for archives")
		extractSample = flag.Bool("sample", false, "Extract and verify first 1MB of each file")
		verbose       = flag.Bool("v", false, "Verbose output")
	)
	flag.Parse()

	if *filePath == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -file <path> [options]\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(1)
	}

	config := &detector.Config{
		MaxCompressionRatio: *maxRatio,
		MaxUncompressedSize: *maxSize,
		MaxNestingDepth:     *maxDepth,
		ExtractSample:       *extractSample,
		Verbose:             *verbose,
	}

	result, err := detector.AnalyzeZIP(detector.NewZIPAnalyzer(config), *filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(result.String())

	if result.IsBomb {
		os.Exit(1)
	}
}
