package nagiosimport

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"chicha-pulse/pkg/model"
)

// This package streams Nagios configs so larger files can be handled without loading everything.

// ---- Types ----

// ObjectKind describes the Nagios object that was parsed.
type ObjectKind int

const (
	KindHost ObjectKind = iota
	KindService
)

// Object carries parsed Nagios data to the rest of the pipeline.
type Object struct {
	Kind      ObjectKind
	Host      model.Host
	Service   model.Service
	HostNames []string
}

// ---- Public API ----

// Stream parses Nagios object files and streams parsed objects.
// It owns the parsing goroutine so downstream code can consume data asynchronously.
func Stream(ctx context.Context, root string) (<-chan Object, <-chan error) {
	filePaths, err := ResolveConfigFiles(ctx, root)
	if err != nil {
		objectCh := make(chan Object)
		errCh := make(chan error, 1)
		close(objectCh)
		errCh <- err
		close(errCh)
		return objectCh, errCh
	}
	return StreamFiles(ctx, filePaths)
}

// StreamFiles parses a list of object files and streams parsed objects.
func StreamFiles(ctx context.Context, files []string) (<-chan Object, <-chan error) {
	objectCh := make(chan Object)
	errCh := make(chan error, 1)

	go func() {
		defer close(objectCh)
		defer close(errCh)

		for _, path := range files {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}
			objects, err := parseFile(path)
			if err != nil {
				errCh <- err
				continue
			}
			for _, obj := range objects {
				select {
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				case objectCh <- obj:
				}
			}
		}
	}()

	return objectCh, errCh
}

// ---- Parsing helpers ----

func parseFile(path string) ([]Object, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseObjects(file)
}

func parseObjects(reader io.Reader) ([]Object, error) {
	scanner := bufio.NewScanner(reader)
	var objects []Object
	var currentType string
	current := map[string]string{}
	inBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "define") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentType = parts[1]
				current = map[string]string{}
				inBlock = true
			}
			continue
		}
		if !inBlock {
			continue
		}
		if line == "}" {
			if obj, ok := buildObject(currentType, current); ok {
				objects = append(objects, obj)
			}
			inBlock = false
			continue
		}
		key, value, ok := splitDirective(line)
		if !ok {
			continue
		}
		current[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return objects, nil
}

func splitDirective(line string) (string, string, bool) {
	index := strings.IndexFunc(line, unicode.IsSpace)
	if index == -1 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:index])
	value := strings.TrimSpace(line[index:])
	value = stripInlineComment(value)
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func stripInlineComment(value string) string {
	for _, marker := range []string{";", "#"} {
		if idx := strings.Index(value, marker); idx >= 0 {
			return strings.TrimSpace(value[:idx])
		}
	}
	return value
}

func buildObject(objectType string, data map[string]string) (Object, bool) {
	switch objectType {
	case "host":
		name := data["host_name"]
		if name == "" {
			return Object{}, false
		}
		parents := splitList(data["parents"])
		host := model.Host{
			Name:    name,
			Address: data["address"],
			Parents: parents,
		}
		return Object{Kind: KindHost, Host: host}, true
	case "service":
		serviceName := data["service_description"]
		hostNames := splitList(data["host_name"])
		if serviceName == "" || len(hostNames) == 0 {
			return Object{}, false
		}
		sshUser, sshKey := parseSSHCommand(data["check_command"])
		service := model.Service{
			Name:                 serviceName,
			CheckCommand:         data["check_command"],
			Notes:                data["notes"],
			NotificationsEnabled: data["notifications_enabled"] != "0",
			Contacts:             splitList(data["contacts"]),
			CheckIntervalMinutes: parseIntervalMinutes(data["check_interval"]),
			SSHUser:              sshUser,
			SSHKeyPath:           sshKey,
		}
		return Object{Kind: KindService, Service: service, HostNames: hostNames}, true
	default:
		return Object{}, false
	}
}

func splitList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	var result []string
	for _, part := range parts {
		clean := strings.TrimSpace(part)
		if clean != "" {
			result = append(result, clean)
		}
	}
	return result
}

func parseIntervalMinutes(value string) int {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 5
	}
	interval, err := strconv.Atoi(trimmed)
	if err != nil || interval <= 0 {
		return 5
	}
	return interval
}

func parseSSHCommand(command string) (string, string) {
	if command == "" {
		return "", ""
	}
	if strings.Contains(command, "check_by_ssh") {
		parts := strings.Split(command, "!")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1]), findKeyPath(parts)
		}
	}
	fields := strings.Fields(command)
	user := ""
	key := ""
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "-l":
			if i+1 < len(fields) {
				user = fields[i+1]
			}
		case "-i":
			if i+1 < len(fields) {
				key = fields[i+1]
			}
		}
	}
	return user, key
}

func findKeyPath(parts []string) string {
	for _, part := range parts {
		if strings.Contains(part, "/") {
			return strings.TrimSpace(part)
		}
	}
	return ""
}
