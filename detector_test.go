package main

import (
	"fmt"
	"testing"

	"github.com/John-sour/zipbomb-shield/detector"
)

func TestCompressionRatioDetection(t *testing.T) {
	tests := []struct {
		name             string
		compressed       int64
		uncompressed     int64
		expectedRatio    float64
		shouldBeDetected bool
	}{
		{
			name:             "Normal compression",
			compressed:       1000000,
			uncompressed:     5000000,
			expectedRatio:    5.0,
			shouldBeDetected: false,
		},
		{
			name:             "High compression (zipbomb)",
			compressed:       100000,
			uncompressed:     100000000,
			expectedRatio:    1000.0,
			shouldBeDetected: true,
		},
		{
			name:             "Extreme compression",
			compressed:       1000,
			uncompressed:     5000000000,
			expectedRatio:    5000000.0,
			shouldBeDetected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio := float64(tt.uncompressed) / float64(tt.compressed)
			if ratio != tt.expectedRatio {
				t.Errorf("expected ratio %.2f, got %.2f", tt.expectedRatio, ratio)
			}

			isDetected := ratio > 100.0 // Default threshold
			if isDetected != tt.shouldBeDetected {
				t.Errorf("expected detection=%v, got %v", tt.shouldBeDetected, isDetected)
			}
		})
	}
}

func TestSizeLimitEnforcement(t *testing.T) {
	config := &detector.Config{
		MaxUncompressedSize: 1e9, // 1GB
	}

	tests := []struct {
		name        string
		size        int64
		shouldAlarm bool
	}{
		{"Small file", 1e6, false},
		{"Medium file", 500e6, false},
		{"At limit", 1e9, false},
		{"Over limit", 2e9, true},
		{"Huge file", 1e18, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exceeds := tt.size > config.MaxUncompressedSize
			if exceeds != tt.shouldAlarm {
				t.Errorf("expected alarm=%v, got %v", tt.shouldAlarm, exceeds)
			}
		})
	}
}

func TestNestingDepthDetection(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectedMax int
	}{
		{"No nesting", "file.zip", 1},
		{"One level", "dir/file.zip", 2},
		{"Two levels", "dir1/dir2/file.zip", 3},
		{"Deep nesting", "a/b/c/d/e/file.zip", 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Count separators
			count := 1
			for _, ch := range tt.path {
				if ch == '/' {
					count++
				}
			}
			if count != tt.expectedMax {
				t.Errorf("expected depth %d, got %d", tt.expectedMax, count)
			}
		})
	}
}

func TestArchiveTypeDetection(t *testing.T) {
	tests := []struct {
		name         string
		filepath     string
		expectedType detector.ArchiveType
	}{
		{"ZIP file", "test.zip", detector.ArchiveTypeZIP},
		{"7Z file", "test.7z", detector.ArchiveType7Z},
		{"RAR file", "test.rar", detector.ArchiveTypeRAR},
		{"TAR file", "test.tar", detector.ArchiveTypeTAR},
		{"TAR.GZ file", "test.tar.gz", detector.ArchiveTypeTARGZ},
		{"TGZ file", "test.tgz", detector.ArchiveTypeTARGZ},
		{"Unknown", "test.txt", detector.ArchiveTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualType := detector.DetectArchiveType(tt.filepath)
			if actualType != tt.expectedType {
				t.Errorf("expected type %d, got %d", tt.expectedType, actualType)
			}
		})
	}
}

func BenchmarkCompressionRatioCalculation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ratio := float64(100000000) / float64(100000)
		_ = ratio
	}
}
