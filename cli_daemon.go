package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/John-sour/zipbomb-shield/detector"
)

func main() {
	var (
		filePath      = flag.String("file", "", "Path to archive file to analyze")
		maxRatio      = flag.Float64("ratio", 100.0, "Maximum allowed compression ratio")
		maxSize       = flag.Int64("max-size", 1e9, "Maximum allowed uncompressed size in bytes")
		maxDepth      = flag.Int("max-depth", 3, "Maximum nesting depth for archives")
		extractSample = flag.Bool("sample", false, "Extract and verify first 1MB of each file")
		extractDir    = flag.String("extract", "", "Extract safely to this directory")
		daemon        = flag.Bool("daemon", false, "Run in daemon mode monitoring directories")
		watchDirs     = flag.String("watch", "", "Comma-separated directories to watch in daemon mode")
		verbose       = flag.Bool("v", false, "Verbose output")
	)
	flag.Parse()

	config := &detector.Config{
		MaxCompressionRatio: *maxRatio,
		MaxUncompressedSize: *maxSize,
		MaxNestingDepth:     *maxDepth,
		ExtractSample:       *extractSample,
		Verbose:             *verbose,
	}

	if *daemon {
		if *watchDirs == "" {
			fmt.Fprintf(os.Stderr, "Usage: %s -daemon -watch </path1>,</path2>\n", os.Args[0])
			os.Exit(1)
		}

		runDaemon(config, *watchDirs)
		return
	}

	if *filePath == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -file <path> [options]\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(1)
	}

	analyzeAndHandle(config, *filePath, *extractDir)
}

func analyzeAndHandle(config *detector.Config, filePath string, extractDir string) {
	archiveType := detector.DetectArchiveType(filePath)

	var result interface{}
	var err error

	switch archiveType {
	case detector.ArchiveTypeZIP:
		result, err = detector.AnalyzeZIP(detector.NewZIPAnalyzer(config), filePath)
	case detector.ArchiveTypeTAR:
		result, err = detector.AnalyzeTAR(config, filePath)
	case detector.ArchiveTypeTARGZ:
		result, err = detector.AnalyzeTARGZ(config, filePath)
	case detector.ArchiveType7Z:
		result, err = detector.Analyze7Z(config, filePath)
	case detector.ArchiveTypeRAR:
		result, err = detector.AnalyzeRAR(config, filePath)
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported archive format\n")
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var isBomb bool
	switch v := result.(type) {
	case *detector.AnalysisResult:
		fmt.Println(v.String())
		isBomb = v.IsBomb
	case *detector.ArchiveAnalysis:
		fmt.Println(v.String())
		isBomb = v.IsBomb
	}

	if extractDir != "" && !isBomb {
		extractor := detector.NewSafeExtractor(config)
		if err := extractor.ExtractWithLimit(filePath, extractDir, config.MaxUncompressedSize); err != nil {
			fmt.Fprintf(os.Stderr, "Extraction error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully extracted to %s\n", extractDir)
	}

	if isBomb {
		os.Exit(1)
	}
}

func runDaemon(config *detector.Config, watchDirs string) {
	dirs := strings.Split(watchDirs, ",")
	daemonConfig := &detector.DaemonConfig{
		WatchDirs:     dirs,
		CheckInterval: 5 * time.Second,
		MaxWorkers:    4,
	}

	monitor := detector.NewArchiveMonitor(config, daemonConfig)
	if err := monitor.Start(); err != nil {
		log.Fatalf("Failed to start monitor: %v", err)
	}

	fmt.Printf("🛡️  ZipBomb Shield daemon started, monitoring: %v\n", dirs)
	fmt.Println("Press Ctrl+C to stop...")

	ctx := context.Background()
	go func() {
		for {
			select {
			case event := <-monitor.Events():
				fmt.Printf("\n🚨 THREAT DETECTED at %s\n", event.Timestamp.Format(time.RFC3339))
				fmt.Println(event.Details)
				// TODO: Add alert mechanism (email, webhook, etc.)
			case <-ctx.Done():
				return
			}
		}
	}()

	select {}
}
