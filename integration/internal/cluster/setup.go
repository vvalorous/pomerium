package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"gopkg.in/yaml.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cmd/pomerium"
	"github.com/pomerium/pomerium/internal/log"
)

// Start starts all the needed servers to facilitate the integration tests.
func Start(ctx context.Context) (*sync.WaitGroup, error) {
	var wg sync.WaitGroup
	var err error

	certsBundle, err := bootstrapCerts(ctx)
	if err != nil {
		return nil, err
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}

	wd := filepath.Join(cacheDir, "pomerium", "integration-tests")
	err = os.MkdirAll(wd, 0755)
	if err != nil {
		return nil, err
	}

	baseOptions := &config.Options{
		Debug:                    true,
		LogLevel:                 "debug",
		SharedKey:                base64.StdEncoding.EncodeToString(getKeyFromPassword("pomerium-shared-key", 32)),
		AuthenticateCallbackPath: "/oauth2/callback",
		CookieSecret:             base64.StdEncoding.EncodeToString(getKeyFromPassword("pomerium-cookie-secret", 32)),
		ClientID:                 "pomerium-authenticate",
		ClientSecret:             "pomerium-authenticate-secret",
		Provider:                 "oidc",
		CacheStore:               "bolt",
	}

	type ProxyDefinition struct {
		Proxy Proxy
		Certs *TLSCerts
	}

	var proxyDefinitions = []ProxyDefinition{
		{Proxy: ProxyAllInOne, Certs: &certsBundle.Trusted},
		{Proxy: ProxySecure, Certs: &certsBundle.Trusted},
		{Proxy: ProxyInsecure, Certs: &certsBundle.Untrusted},
	}

	for _, proxyDefinition := range proxyDefinitions {
		proxy := proxyDefinition.Proxy
		for _, options := range proxy.GetPomeriumConfigs(baseOptions) {
			options := options

			if proxyDefinition.Certs != nil {
				options.CA = base64.StdEncoding.EncodeToString(proxyDefinition.Certs.CA)
				options.Cert = base64.StdEncoding.EncodeToString(proxyDefinition.Certs.Cert)
				options.Key = base64.StdEncoding.EncodeToString(proxyDefinition.Certs.Key)
			}

			bs, err := yaml.Marshal(options)
			if err != nil {
				return nil, err
			}

			name := filepath.Join(wd, fmt.Sprintf("pomerium-config-%x.yaml", options.Checksum()))

			err = ioutil.WriteFile(name, bs, 0644)
			if err != nil {
				return nil, err
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := pomerium.Run(ctx, name); err != nil {
					if ctx.Err() == nil {
						log.Error().Err(err).Str("config-file", name).Str("proxy", proxy.String()).Str("service", options.Services).Msg("failed to run pomerium")
					}
				}
			}()
		}

	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	waitCtx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	// wait for them to come up
	for _, proxy := range []Proxy{ProxyAllInOne} {
		port := proxy.DownstreamPort(EndpointPomeriumProxy)
		for {
			conn, err := (&net.Dialer{}).DialContext(waitCtx, "tcp", net.JoinHostPort("localhost", strconv.Itoa(port)))
			if err == nil {
				conn.Close()
				break
			}

			select {
			case <-waitCtx.Done():
				return &wg, waitCtx.Err()
			case <-ticker.C:
			}
		}
	}

	time.Sleep(time.Second * 3)

	return &wg, nil
}

func getKeyFromPassword(password string, sz int) []byte {
	bs := make([]byte, sz)
	_, err := io.ReadFull(hkdf.New(sha256.New, []byte(password), nil, nil), bs)
	if err != nil {
		panic(err)
	}
	return bs
}
