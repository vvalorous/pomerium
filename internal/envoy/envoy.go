package envoy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/natefinch/atomic"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

const (
	workingDirectoryName = ".pomerium-envoy"
	configFileName       = "envoy-config.json"
)

// A Server is a pomerium proxy implemented via envoy.
type Server struct {
	wd  string
	cmd *exec.Cmd
}

// NewServer creates a new server with traffic routed by envoy.
func NewServer(options *config.Options, wg *sync.WaitGroup) (*Server, error) {
	wd := filepath.Join(os.TempDir(), workingDirectoryName)
	err := os.MkdirAll(wd, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating temporary working directory for envoy: %w", err)
	}

	srv := &Server{
		wd: wd,
	}

	err = srv.writeConfig(options)
	if err != nil {
		return nil, fmt.Errorf("error writing initial envoy configuration: %w", err)
	}

	err = srv.startEnvoy()
	if err != nil {
		return nil, fmt.Errorf("error starting envoy: %w", err)
	}

	go srv.handleSignals()

	wg.Add(1)
	defer wg.Done()
	return srv, nil
}

// Shutdown attempts to shutdown the envoy server.
func (srv *Server) Shutdown(ctx context.Context) error {
	err := srv.cmd.Process.Signal(os.Interrupt)
	if err != nil {
		return err
	}

	waitchan := make(chan error, 1)
	go func() {
		waitchan <- srv.cmd.Wait()
	}()

	select {
	case err := <-waitchan:
		return err
	case <-ctx.Done():
		return fmt.Errorf("process did not terminate in time")
	}
}

// UpdateOptions is called whenenver options in config are updated.
func (srv *Server) UpdateOptions(options config.Options) error {
	return srv.writeConfig(&options)
}

func (srv *Server) handleSignals() {
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	signal.Notify(sigint, syscall.SIGTERM)
	rec := <-sigint

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Info().Str("signal", rec.String()).Msg("internal/envoy: shutting down server")
	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("internal/httputil: shutdown failed")
	}
}

func (srv *Server) startEnvoy() error {
	srv.cmd = exec.Command("envoy", "-c", configFileName, "--log-level", "debug")
	srv.cmd.Dir = srv.wd
	srv.cmd.Stdout = os.Stdout
	srv.cmd.Stderr = os.Stderr
	err := srv.cmd.Start()
	if err != nil {
		return err
	}
	return nil
}

func (srv *Server) writeConfig(options *config.Options) error {
	bootstrap := GetBootstrapConfig(options)
	bs, err := json.Marshal(bootstrap)
	if err != nil {
		return err
	}
	return atomic.WriteFile(filepath.Join(srv.wd, configFileName), bytes.NewReader(bs))
}
