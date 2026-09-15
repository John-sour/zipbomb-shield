package detector

import (
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SafeExtractor safely extracts archives with resource limits
type SafeExtractor struct {
	config       *Config
	maxPerFile   int64
	tempDir      string
	extractedMu  sync.Mutex
	extractedMap map[string]int64
}

// NewSafeExtractor creates a new safe extractor
func NewSafeExtractor(config *Config) *SafeExtractor {
	return &SafeExtractor{
		config:         config,
		maxPerFile:     1e6, // 1MB per file by default
		tempDir:        "",
		extractedMap:   make(map[string]int64),
	}
}

// LimitedReader enforces size limits during extraction
type LimitedReader struct {
	reader io.Reader
	limit  int64
	read   int64
}

// Read implements io.Reader with size limit
func (lr *LimitedReader) Read(p []byte) (n int, err error) {
	if lr.read >= lr.limit {
		return 0, fmt.Errorf("extraction size limit exceeded: %d bytes", lr.read)
	}

	if int64(len(p))+lr.read > lr.limit {
		p = p[:lr.limit-lr.read]
	}

	n, err = lr.reader.Read(p)
	lr.read += int64(n)
	return n, err
}

// ExtractWithLimit safely extracts archive with size limits
func (se *SafeExtractor) ExtractWithLimit(archivePath string, outputDir string, maxTotalSize int64) error {
	if outputDir == "" {
		// Use secure temp directory
		tmpDir, err := os.MkdirTemp("", "zipbomb-shield-*")
		if err != nil {
			return fmt.Errorf("failed to create temp dir: %w", err)
		}
		outputDir = tmpDir
	}

	archiveType := DetectArchiveType(archivePath)

	switch archiveType {
	case ArchiveTypeZIP:
		return se.extractZIPSafe(archivePath, outputDir, maxTotalSize)
	case ArchiveTypeTARGZ:
		return se.extractTARGZSafe(archivePath, outputDir, maxTotalSize)
	case ArchiveTypeTAR:
		return se.extractTARSafe(archivePath, outputDir, maxTotalSize)
	default:
		return fmt.Errorf("unsupported archive format")
	}
}

func (se *SafeExtractor) extractZIPSafe(archivePath string, outputDir string, maxTotalSize int64) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open ZIP: %w", err)
	}
	defer reader.Close()

	var totalExtracted int64

	for _, file := range reader.File {
		// Check size limits
		if file.UncompressedSize64 > se.config.MaxUncompressedSize {
			return fmt.Errorf("file %s exceeds size limit", file.Name)
		}

		totalExtracted += file.UncompressedSize64
		if totalExtracted > maxTotalSize {
			return fmt.Errorf("total extraction size exceeds limit")
		}

		// Create output path
		outputPath := filepath.Join(outputDir, file.Name)
		if !isPathSafe(outputPath, outputDir) {
			return fmt.Errorf("path traversal detected: %s", file.Name)
		}

		// Create directories
		if file.FileInfo().IsDir() {
			os.MkdirAll(outputPath, 0755)
			continue
		}

		os.MkdirAll(filepath.Dir(outputPath), 0755)

		// Extract with limit
		rc, err := file.Open()
		if err != nil {
			return err
		}

		limitedReader := &LimitedReader{
			reader: rc,
			limit:  file.UncompressedSize64,
		}

		outFile, err := os.Create(outputPath)
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(outFile, limitedReader)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}

	return nil
}

func (se *SafeExtractor) extractTARGZSafe(archivePath string, outputDir string, maxTotalSize int64) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to read gzip: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var totalExtracted int64

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.Size > se.config.MaxUncompressedSize {
			return fmt.Errorf("file %s exceeds size limit", header.Name)
		}

		totalExtracted += header.Size
		if totalExtracted > maxTotalSize {
			return fmt.Errorf("total extraction size exceeds limit")
		}

		outputPath := filepath.Join(outputDir, header.Name)
		if !isPathSafe(outputPath, outputDir) {
			return fmt.Errorf("path traversal detected: %s", header.Name)
		}

		if header.Typeflag == tar.TypeDir {
			os.MkdirAll(outputPath, 0755)
			continue
		}

		os.MkdirAll(filepath.Dir(outputPath), 0755)
		outFile, err := os.Create(outputPath)
		if err != nil {
			return err
		}

		_, err = io.CopyN(outFile, tarReader, header.Size)
		outFile.Close()
		if err != nil && err != io.EOF {
			return err
		}
	}

	return nil
}

func (se *SafeExtractor) extractTARSafe(archivePath string, outputDir string, maxTotalSize int64) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	tarReader := tar.NewReader(file)
	var totalExtracted int64

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.Size > se.config.MaxUncompressedSize {
			return fmt.Errorf("file %s exceeds size limit", header.Name)
		}

		totalExtracted += header.Size
		if totalExtracted > maxTotalSize {
			return fmt.Errorf("total extraction size exceeds limit")
		}

		outputPath := filepath.Join(outputDir, header.Name)
		if !isPathSafe(outputPath, outputDir) {
			return fmt.Errorf("path traversal detected: %s", header.Name)
		}

		if header.Typeflag == tar.TypeDir {
			os.MkdirAll(outputPath, 0755)
			continue
		}

		os.MkdirAll(filepath.Dir(outputPath), 0755)
		outFile, err := os.Create(outputPath)
		if err != nil {
			return err
		}

		_, err = io.CopyN(outFile, tarReader, header.Size)
		outFile.Close()
		if err != nil && err != io.EOF {
			return err
		}
	}

	return nil
}

// isPathSafe checks for path traversal attacks
func isPathSafe(outputPath string, baseDir string) bool {
	abs, err := filepath.Abs(outputPath)
	if err != nil {
		return false
	}

	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}

	relative, err := filepath.Rel(baseAbs, abs)
	if err != nil {
		return false
	}

	return !strings.HasPrefix(relative, "..")
}

// ComputeFileHash computes MD5 hash of extracted file for verification
func ComputeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
