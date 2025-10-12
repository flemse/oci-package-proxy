package testutils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func StartTestContainer(ctx context.Context) (string, error) {
	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/project-zot/zot:latest",
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForLog("starting task"),
	}
	zotContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return "", fmt.Errorf("could not start zot container: %w", err)
	}
	h, err := zotContainer.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("could not get zot container host: %w", err)
	}
	p, err := zotContainer.MappedPort(ctx, "5000")
	if err != nil {
		return "", fmt.Errorf("could not get zot container port: %w", err)
	}

	return fmt.Sprintf("%s:%s", h, p.Port()), nil
}

func ReadExecOutput(reader io.Reader) string {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(reader)
	output := buf.Bytes()

	var result bytes.Buffer
	for len(output) > 0 {
		if len(output) < 8 {
			// If less than 8 bytes, just append what's left
			result.Write(output)
			break
		}
		// Read the payload size from bytes 4-7 (big-endian)
		payloadSize := int(output[4])<<24 | int(output[5])<<16 | int(output[6])<<8 | int(output[7])
		if payloadSize == 0 || len(output) < 8+payloadSize {
			// Invalid header or incomplete payload, return what we have
			result.Write(output[8:])
			break
		}
		// Extract payload
		result.Write(output[8 : 8+payloadSize])
		output = output[8+payloadSize:]
	}
	return strings.TrimSpace(result.String())
}

func StartPythonTestContainer(ctx context.Context) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:      "python:3.11-slim",
		WaitingFor: wait.ForLog(""),
		Cmd:        []string{"sleep", "infinity"},
	}

	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}
