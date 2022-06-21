package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// nolint:paralleltest
func Test_absoluteBinaryPath(t *testing.T) {
	t.Skip("Skipping for debugging.")
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name             string
		args             args
		terraformVersion string
		expectedOk       bool
	}{
		{
			name:             "TestCorrectVersion",
			args:             args{ctx: context.Background()},
			terraformVersion: "1.1.9",
			expectedOk:       true,
		},
		{
			name:             "TestOldVersion",
			args:             args{ctx: context.Background()},
			terraformVersion: "1.0.9",
			expectedOk:       false,
		},
		{
			name:             "TestNewVersion",
			args:             args{ctx: context.Background()},
			terraformVersion: "1.2.9",
			expectedOk:       false,
		},
		{
			name:             "TestMalformedVersion",
			args:             args{ctx: context.Background()},
			terraformVersion: "version",
			expectedOk:       false,
		},
	}
	// nolint:paralleltest
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("Dummy terraform executable on Windows requires sh which isn't very practical.")
			}

			// Create a temp dir with the binary
			tempDir := t.TempDir()
			terraformBinaryOutput := fmt.Sprintf(`#!/bin/sh
			cat <<-EOF
			{
				"terraform_version": "%s",
				"platform": "linux_amd64",
				"provider_selections": {},
				"terraform_outdated": false
			}
			EOF`, tt.terraformVersion)

			// #nosec
			err := os.WriteFile(
				filepath.Join(tempDir, "terraform"),
				[]byte(terraformBinaryOutput),
				0770,
			)
			require.NoError(t, err)

			// Add the binary to PATH
			pathVariable := os.Getenv("PATH")
			t.Setenv("PATH", strings.Join([]string{tempDir, pathVariable}, ":"))

			var expectedAbsoluteBinary string
			if tt.expectedOk {
				expectedAbsoluteBinary = filepath.Join(tempDir, "terraform")
			}

			actualAbsoluteBinary, actualOk := absoluteBinaryPath(tt.args.ctx)
			if actualAbsoluteBinary != expectedAbsoluteBinary {
				t.Errorf("getAbsoluteBinaryPath() absoluteBinaryPath, actual = %v, expected %v", actualAbsoluteBinary, expectedAbsoluteBinary)
			}
			if actualOk != tt.expectedOk {
				t.Errorf("getAbsoluteBinaryPath() ok, actual = %v, expected %v", actualOk, tt.expectedOk)
			}
		})
	}
}
