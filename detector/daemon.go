package detector

import (
	"fmt"
	"sync"
	"time"
)

// DaemonConfig holds daemon configuration
type DaemonConfig struct {
	WatchDirs     []string
	CheckInterval time.Duration
	MaxWorkers    int
}

// DaemonEvent represents a detection event
type DaemonEvent struct {
	FilePath  string
	Timestamp time.Time
	IsBomb    bool
	Details   string
}

// ArchiveMonitor monitors directories for suspicious archives
type ArchiveMonitor struct {
	config    *Config
	daemonCfg *DaemonConfig
	events    chan DaemonEvent
	done      chan bool
	wg        sync.WaitGroup
}

// NewArchiveMonitor creates a new monitor
func NewArchiveMonitor(config *Config, daemonCfg *DaemonConfig) *ArchiveMonitor {
	return &ArchiveMonitor{
		config:    config,
		daemonCfg: daemonCfg,
		events:    make(chan DaemonEvent, 100),
		done:      make(chan bool),
	}
}

// Start begins monitoring directories
func (am *ArchiveMonitor) Start() error {
	if len(am.daemonCfg.WatchDirs) == 0 {
		return fmt.Errorf("no directories to watch")
	}

	am.wg.Add(1)
	go am.monitorLoop()

	return nil
}

// Stop stops the monitor
func (am *ArchiveMonitor) Stop() {
	close(am.done)
	am.wg.Wait()
}

// Events returns the event channel
func (am *ArchiveMonitor) Events() <-chan DaemonEvent {
	return am.events
}

func (am *ArchiveMonitor) monitorLoop() {
	defer am.wg.Done()
	ticker := time.NewTicker(am.daemonCfg.CheckInterval)
	defer ticker.Stop()

	processedFiles := make(map[string]time.Time)

	for {
		select {
		case <-am.done:
			return
		case <-ticker.C:
			am.scanDirectories(processedFiles)
		}
	}
}

func (am *ArchiveMonitor) scanDirectories(processedFiles map[string]time.Time) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, am.daemonCfg.MaxWorkers)

	for _, dir := range am.daemonCfg.WatchDirs {
		wg.Add(1)
		go func(watchDir string) {
			defer wg.Done()
			am.scanDirectory(watchDir, processedFiles, semaphore)
		}(dir)
	}

	wg.Wait()
}

func (am *ArchiveMonitor) scanDirectory(dir string, processedFiles map[string]time.Time, semaphore chan struct{}) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		arcType := DetectArchiveType(filePath)

		if arcType == ArchiveTypeUnknown {
			continue
		}

		fileInfo, err := entry.Info()
		if err != nil {
			continue
		}

		lastProcessed, exists := processedFiles[filePath]
		if exists && fileInfo.ModTime().Equal(lastProcessed) {
			continue
		}

		semaphore <- struct{}{}
		go func(path string, info os.FileInfo) {
			defer func() { <-semaphore }()
			am.analyzeArchive(path, info, processedFiles)
		}(filePath, fileInfo)
	}
}

func (am *ArchiveMonitor) analyzeArchive(filePath string, fileInfo os.FileInfo, processedFiles map[string]time.Time) {
	var result interface{}
	var err error

	archiveType := DetectArchiveType(filePath)
	switch archiveType {
	case ArchiveTypeZIP:
		analysis, _ := AnalyzeZIP(NewZIPAnalyzer(am.config), filePath)
		result = analysis
	case ArchiveTypeTARGZ:
		result, err = AnalyzeTARGZ(am.config, filePath)
	case ArchiveTypeTAR:
		result, err = AnalyzeTAR(am.config, filePath)
	default:
		return
	}

	if err != nil {
		return
	}

	var isBomb bool
	var details string

	switch v := result.(type) {
	case *ArchiveAnalysis:
		isBomb = v.IsBomb
		details = v.String()
	case *AnalysisResult:
		isBomb = v.IsBomb
		details = v.String()
	}

	if isBomb {
		am.events <- DaemonEvent{
			FilePath:  filePath,
			Timestamp: time.Now(),
			IsBomb:    true,
			Details:   details,
		}
	}

	processedFiles[filePath] = fileInfo.ModTime()
}
