package envoy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/natefinch/atomic"
	"github.com/pomerium/pomerium/config"
)

const (
	workingDirectoryName = ".pomerium-envoy"
	configFileName       = "envoy-config.yaml"
)

// A Server is a pomerium proxy implemented via envoy.
type Server struct {
	wd  string
	cmd *exec.Cmd

	grpcPort, httpPort string
}

// NewServer creates a new server with traffic routed by envoy.
func NewServer(options *config.Options, grpcPort, httpPort string) (*Server, error) {
	wd := filepath.Join(os.TempDir(), workingDirectoryName)
	err := os.MkdirAll(wd, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating temporary working directory for envoy: %w", err)
	}

	srv := &Server{
		wd:       wd,
		grpcPort: grpcPort,
		httpPort: httpPort,
	}

	err = srv.writeConfig(options)
	if err != nil {
		return nil, fmt.Errorf("error writing initial envoy configuration: %w", err)
	}

	return srv, nil
}

func (srv *Server) Run(ctx context.Context) error {
	srv.cmd = exec.CommandContext(ctx, "envoy", "-c", configFileName, "--log-level", "debug")
	srv.cmd.Dir = srv.wd
	srv.cmd.Stdout = os.Stdout
	srv.cmd.Stderr = os.Stderr
	return srv.cmd.Run()
}

func (srv *Server) writeConfig(options *config.Options) error {
	// bootstrap := GetBootstrapConfig(options)
	// bs, err := json.Marshal(bootstrap)
	// if err != nil {
	// 	return err
	// }
	// return atomic.WriteFile(filepath.Join(srv.wd, configFileName), bytes.NewReader(bs))

	return atomic.WriteFile(filepath.Join(srv.wd, configFileName), strings.NewReader(`
node:
  id: pomerium-envoy
  cluster: pomerium-envoy

admin:
  access_log_path: /tmp/admin_access.log
  address:
    socket_address: { address: 127.0.0.1, port_value: 9901 }

dynamic_resources:
  cds_config:
    ads: {}
    resource_api_version: V3
  lds_config:
    ads: {}
    resource_api_version: V3
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc:
          cluster_name: pomerium-control-plane-grpc
static_resources:
  clusters:
  - name: pomerium-control-plane-grpc
    connect_timeout: { seconds: 5 }
    type: STATIC
    hosts:
    - socket_address:
        address: 127.0.0.1
        port_value: `+srv.grpcPort+`
    http2_protocol_options: {}
`))
}
