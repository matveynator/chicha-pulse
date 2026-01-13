package nagiosimport

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// This file keeps Nagios configuration discovery separate from object parsing.

// ---- Config discovery ----

// ResolveConfigFiles expands a Nagios config file or directory into object file paths.
func ResolveConfigFiles(ctx context.Context, root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return discoverConfigDir(ctx, root)
	}
	return discoverConfigFile(ctx, root)
}

func discoverConfigDir(ctx context.Context, root string) ([]string, error) {
	return walkConfigs(ctx, root)
}

func discoverConfigFile(ctx context.Context, root string) ([]string, error) {
	file, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	baseDir := filepath.Dir(root)
	scanner := bufio.NewScanner(file)
	var files []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "cfg_file") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "cfg_file"))
			value = strings.TrimLeft(value, "=")
			value = strings.TrimSpace(value)
			value = resolvePath(baseDir, value)
			if value != "" {
				files = append(files, value)
			}
			continue
		}
		if strings.HasPrefix(line, "cfg_dir") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "cfg_dir"))
			value = strings.TrimLeft(value, "=")
			value = strings.TrimSpace(value)
			value = resolvePath(baseDir, value)
			if value == "" {
				continue
			}
			paths, err := walkConfigs(ctx, value)
			if err != nil {
				return nil, err
			}
			files = append(files, paths...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("no Nagios config files discovered")
	}
	return files, nil
}

func resolvePath(baseDir, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func walkConfigs(ctx context.Context, root string) ([]string, error) {
	var files []string
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".cfg") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			files = append(files, path)
			return nil
		}
	})
	if walkErr != nil && !errors.Is(walkErr, context.Canceled) {
		return nil, walkErr
	}
	return files, nil
}
