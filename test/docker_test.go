package main

import (
	"context"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func startContainer(cfg *container.Config, hostCfg *container.HostConfig, name string) (string, error) {
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}
	defer c.Close()

	if !isDarwin {
		hostCfg.NetworkMode = "host"
	}

	created, err := c.ContainerCreate(context.Background(), cfg, hostCfg, nil, nil, name)
	if err != nil {
		return "", err
	}

	if err = c.ContainerStart(context.Background(), created.ID, container.StartOptions{}); err != nil {
		return "", err
	}

	response, err := c.ContainerAttach(context.Background(), created.ID, container.AttachOptions{
		Stdout: true,
		Stderr: true,
		Logs:   true,
	})
	if err != nil {
		return "", err
	}

	go func() {
		response.Reader.WriteTo(os.Stderr)
	}()

	return created.ID, nil
}

func cleanContainer(id string) error {
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer c.Close()

	removeOpts := container.RemoveOptions{Force: true}
	return c.ContainerRemove(context.Background(), id, removeOpts)
}
