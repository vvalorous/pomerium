package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"sync"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/cache"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/envoy"
	pgrpc "github.com/pomerium/pomerium/internal/grpc"
	pbAuthorize "github.com/pomerium/pomerium/internal/grpc/authorize"
	pbCache "github.com/pomerium/pomerium/internal/grpc/cache"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/proxy"
	"golang.org/x/sync/errgroup"

	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

var versionFlag = flag.Bool("version", false, "prints the version")
var configFile = flag.String("config", "", "Specify configuration file location")

func main() {
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("cmd/pomerium")
	}
}

func run() error {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.FullVersion())
		return nil
	}
	opt, err := config.NewOptionsFromConfig(*configFile)
	if err != nil {
		return err
	}
	var optionsUpdaters []config.OptionsUpdater

	log.Info().Str("version", version.FullVersion()).Msg("cmd/pomerium")

	ctx := context.Background()

	// setup the control plane
	controlPlane, err := controlplane.NewServer()
	if err != nil {
		return fmt.Errorf("error creating control plane: %w", err)
	}
	optionsUpdaters = append(optionsUpdaters, controlPlane)
	err = controlPlane.UpdateOptions(*opt)
	if err != nil {
		return fmt.Errorf("error updating control plane options: %w", err)
	}

	_, grpcPort, _ := net.SplitHostPort(controlPlane.GRPCListener.Addr().String())
	_, httpPort, _ := net.SplitHostPort(controlPlane.HTTPListener.Addr().String())

	//
	envoyServer, err := envoy.NewServer(opt, grpcPort, httpPort)
	if err != nil {
		return fmt.Errorf("error creating envoy server")
	}

	// add services
	if config.IsAuthenticate(opt.Services) {
		svc, err := authenticate.New(*opt)
		if err != nil {
			return fmt.Errorf("error creating authenticate service: %w", err)
		}
		host := urlutil.StripPort(opt.AuthenticateURL.Host)
		sr := controlPlane.HTTPRouter.Host(host).Subrouter()
		svc.Mount(sr)
		log.Info().Str("host", host).Msg("enabled authenticate service")
	}

	if config.IsAuthorize(opt.Services) {
		svc, err := authorize.New(*opt)
		if err != nil {
			return fmt.Errorf("error creating authorize service: %w", err)
		}
		pbAuthorize.RegisterAuthorizerServer(controlPlane.GRPCServer, svc)
		envoy_service_auth_v2.RegisterAuthorizationServer(controlPlane.GRPCServer, svc)

		log.Info().Msg("enabled authorize service")

		optionsUpdaters = append(optionsUpdaters, svc)
		err = svc.UpdateOptions(*opt)
		if err != nil {
			return fmt.Errorf("error updating authorize options: %w", err)
		}
	}

	if config.IsCache(opt.Services) {
		svc, err := cache.New(*opt)
		if err != nil {
			return fmt.Errorf("error creating config service: %w", err)
		}
		defer svc.Close()
		pbCache.RegisterCacheServer(controlPlane.GRPCServer, svc)
		log.Info().Msg("enabled cache service")
	}

	if config.IsProxy(opt.Services) {
		svc, err := proxy.New(*opt)
		if err != nil {
			return fmt.Errorf("error creating proxy service: %w", err)
		}
		controlPlane.HTTPRouter.PathPrefix("/").Handler(svc)
	}

	// start the config change listener
	opt.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("cmd/pomerium: config file changed")
		opt = config.HandleConfigUpdate(*configFile, opt, optionsUpdaters)
	})

	// run everything
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return controlPlane.Run(ctx)
	})
	eg.Go(func() error {
		return envoyServer.Run(ctx)
	})
	return eg.Wait()

	// since we can have multiple listeners, we create a wait group
	// var wg sync.WaitGroup
	// if err := setupMetrics(opt, &wg); err != nil {
	// 	return err
	// }
	// if err := setupTracing(opt); err != nil {
	// 	return err
	// }
	// if err := setupHTTPRedirectServer(opt, &wg); err != nil {
	// 	return err
	// }

	// r := newGlobalRouter(opt)
	// _, err = newAuthenticateService(*opt, r)
	// if err != nil {
	// 	return err
	// }
	// authz, err := newAuthorizeService(*opt)
	// if err != nil {
	// 	return err
	// }
	// optionsUpdaters = append(optionsUpdaters, authz)

	// cacheSvc, err := newCacheService(*opt)
	// if err != nil {
	// 	return err
	// }
	// if cacheSvc != nil {
	// 	defer cacheSvc.Close()
	// }

	// // new envoy mode!
	// if true {
	// 	hopt := httpServerOptions(opt)
	// 	hopt.Addr = "127.0.0.1:5080"
	// 	controlServer, err := httputil.NewServer(hopt, r, &wg)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	go httputil.Shutdown(controlServer)

	// 	srv, err := envoy.NewServer(opt, &wg)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	optionsUpdaters = append(optionsUpdaters, srv)
	// } else {
	// 	proxy, err := newProxyService(*opt, r)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	if proxy != nil {
	// 		defer proxy.AuthorizeClient.Close()
	// 	}
	// 	optionsUpdaters = append(optionsUpdaters, proxy)

	// 	srv, err := httputil.NewServer(httpServerOptions(opt), r, &wg)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	go httputil.Shutdown(srv)
	// }

	// if err := newGRPCServer(*opt, authz, cacheSvc, &wg); err != nil {
	// 	return err
	// }

	// opt.OnConfigChange(func(e fsnotify.Event) {
	// 	log.Info().Str("file", e.Name).Msg("cmd/pomerium: config file changed")
	// 	opt = config.HandleConfigUpdate(*configFile, opt, optionsUpdaters)
	// })

	// // Blocks and waits until ALL WaitGroup members have signaled completion
	// wg.Wait()
	// return nil
}

func newAuthenticateService(opt config.Options, r *mux.Router) (*authenticate.Authenticate, error) {
	if !config.IsAuthenticate(opt.Services) {
		return nil, nil
	}
	service, err := authenticate.New(opt)
	if err != nil {
		return nil, err
	}
	sr := r.Host(urlutil.StripPort(opt.AuthenticateURL.Host)).Subrouter()
	sr.PathPrefix("/").Handler(service.Handler())

	return service, nil
}

func newAuthorizeService(opt config.Options) (*authorize.Authorize, error) {
	if !config.IsAuthorize(opt.Services) {
		return nil, nil
	}
	return authorize.New(opt)
}

func newCacheService(opt config.Options) (*cache.Cache, error) {
	if !config.IsCache(opt.Services) {
		return nil, nil
	}
	return cache.New(opt)
}

func newGRPCServer(opt config.Options, as *authorize.Authorize, cs *cache.Cache, wg *sync.WaitGroup) error {
	if as == nil && cs == nil {
		return nil
	}
	regFn := func(s *grpc.Server) {
		if as != nil {
			pbAuthorize.RegisterAuthorizerServer(s, as)
		}
		if cs != nil {
			pbCache.RegisterCacheServer(s, cs)

		}
	}
	so := &pgrpc.ServerOptions{
		Addr:        opt.GRPCAddr,
		ServiceName: opt.Services,
		KeepaliveParams: keepalive.ServerParameters{
			MaxConnectionAge:      opt.GRPCServerMaxConnectionAge,
			MaxConnectionAgeGrace: opt.GRPCServerMaxConnectionAgeGrace,
		},
	}
	if !opt.GRPCInsecure {
		so.TLSCertificate = opt.TLSCertificate
	}
	grpcSrv, err := pgrpc.NewServer(so, regFn, wg)
	if err != nil {
		return err
	}
	go pgrpc.Shutdown(grpcSrv)
	return nil
}

func newProxyService(opt config.Options, r *mux.Router) (*proxy.Proxy, error) {
	if !config.IsProxy(opt.Services) {
		return nil, nil
	}
	service, err := proxy.New(opt)
	if err != nil {
		return nil, err
	}
	r.PathPrefix("/").Handler(service)
	return service, nil
}

func setupMetrics(opt *config.Options, wg *sync.WaitGroup) error {
	if opt.MetricsAddr != "" {
		handler, err := metrics.PrometheusHandler()
		if err != nil {
			return err
		}
		metrics.SetBuildInfo(opt.Services)
		metrics.RegisterInfoMetrics()
		serverOpts := &httputil.ServerOptions{Addr: opt.MetricsAddr}
		srv, err := httputil.NewServer(serverOpts, handler, wg)
		if err != nil {
			return err
		}
		go httputil.Shutdown(srv)
	}
	return nil
}

func setupTracing(opt *config.Options) error {
	if opt.TracingProvider != "" {
		tracingOpts := &trace.TracingOptions{
			Provider:                opt.TracingProvider,
			Service:                 opt.Services,
			Debug:                   opt.TracingDebug,
			JaegerAgentEndpoint:     opt.TracingJaegerAgentEndpoint,
			JaegerCollectorEndpoint: opt.TracingJaegerCollectorEndpoint,
		}
		if err := trace.RegisterTracing(tracingOpts); err != nil {
			return err
		}
	}
	return nil
}

func setupHTTPRedirectServer(opt *config.Options, wg *sync.WaitGroup) error {
	if opt.HTTPRedirectAddr != "" {
		serverOpts := httputil.ServerOptions{Addr: opt.HTTPRedirectAddr}
		srv, err := httputil.NewServer(&serverOpts, httputil.RedirectHandler(), wg)
		if err != nil {
			return err
		}
		go httputil.Shutdown(srv)
	}
	return nil
}

func httpServerOptions(opt *config.Options) *httputil.ServerOptions {
	return &httputil.ServerOptions{
		Addr:              opt.Addr,
		TLSCertificate:    opt.TLSCertificate,
		ReadTimeout:       opt.ReadTimeout,
		WriteTimeout:      opt.WriteTimeout,
		ReadHeaderTimeout: opt.ReadHeaderTimeout,
		IdleTimeout:       opt.IdleTimeout,
	}
}
