package controlplane

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_network_http_connection_manager_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func (srv *Server) registerXDSHandlers() {
	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv.GRPCServer, srv)
}

func (srv *Server) StreamAggregatedResources(stream envoy_service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	versions := map[string]string{}
	incoming := make(chan *envoy_service_discovery_v3.DiscoveryRequest)
	outgoing := make(chan *envoy_service_discovery_v3.DiscoveryResponse)

	eg, ctx := errgroup.WithContext(stream.Context())
	// receive requests
	eg.Go(func() error {
		for {
			req, err := stream.Recv()
			if err != nil {
				return err
			}

			log.Info().
				Str("version_info", req.VersionInfo).
				Str("node", req.Node.Id).
				Strs("resource_names", req.ResourceNames).
				Str("type_url", req.TypeUrl).
				Str("response_nonce", req.ResponseNonce).
				Msg("received discovery request")

			select {
			case incoming <- req:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	eg.Go(func() error {
		for {
			select {
			case req := <-incoming:
				versions[req.TypeUrl] = req.VersionInfo
			case <-srv.configUpdated:
			case <-ctx.Done():
				return ctx.Err()
			}

			current := srv.currentConfig.Load().(versionedOptions)
			for typeURL, version := range versions {
				if version != fmt.Sprint(current.version) {
					res, err := srv.buildDiscoveryResponse(fmt.Sprint(current.version), typeURL, current.Options)
					if err != nil {
						return err
					}
					select {
					case outgoing <- res:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}
		}
	})
	// send responses
	eg.Go(func() error {
		for {
			var res *envoy_service_discovery_v3.DiscoveryResponse
			select {
			case res = <-outgoing:
			case <-ctx.Done():
				return ctx.Err()
			}

			err := stream.Send(res)
			if err != nil {
				return err
			}
		}
	})
	return eg.Wait()
}

func (srv *Server) DeltaAggregatedResources(in envoy_service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	return fmt.Errorf("DeltaAggregatedResources not implemented")
}

func (srv *Server) buildDiscoveryResponse(version string, typeURL string, options config.Options) (*envoy_service_discovery_v3.DiscoveryResponse, error) {
	switch typeURL {
	case "type.googleapis.com/envoy.config.listener.v3.Listener":
		listeners := srv.buildListeners(options)
		anys := make([]*any.Any, len(listeners))
		for i, listener := range listeners {
			a, err := ptypes.MarshalAny(listener)
			if err != nil {
				return nil, grpc.Errorf(codes.Internal, "error marshaling type to any: %v", err)
			}
			anys[i] = a
		}
		return &envoy_service_discovery_v3.DiscoveryResponse{
			VersionInfo: version,
			Resources:   anys,
			TypeUrl:     typeURL,
		}, nil
	case "type.googleapis.com/envoy.config.cluster.v3.Cluster":
		clusters := srv.buildClusters(options)
		anys := make([]*any.Any, len(clusters))
		for i, cluster := range clusters {
			a, err := ptypes.MarshalAny(cluster)
			if err != nil {
				return nil, grpc.Errorf(codes.Internal, "error marshaling type to any: %v", err)
			}
			anys[i] = a
		}
		return &envoy_service_discovery_v3.DiscoveryResponse{
			VersionInfo: version,
			Resources:   anys,
			TypeUrl:     typeURL,
		}, nil
	default:
		return nil, grpc.Errorf(codes.Internal, "received request for unknown discovery request type: %s", typeURL)
	}
}

func (srv *Server) buildListeners(options config.Options) []*envoy_config_listener_v3.Listener {
	var listeners []*envoy_config_listener_v3.Listener

	// address => insecure
	liTypes := map[string]bool{}
	if config.IsAuthenticate(options.Services) || config.IsProxy(options.Services) {
		liTypes[options.Addr] = options.InsecureServer
	}
	if config.IsAuthorize(options.Services) || config.IsCache(options.Services) {
		liTypes[options.GRPCAddr] = options.GRPCInsecure
	}
	var addrs []string
	for addr := range liTypes {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	for i, addr := range addrs {
		isInsecure := liTypes[addr]

		tc, _ := ptypes.MarshalAny(&envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{
			CodecType:  envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager_AUTO,
			StatPrefix: "ingress",
			RouteSpecifier: &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig{
				RouteConfig: &envoy_config_route_v3.RouteConfiguration{
					Name: "control-plane",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						srv.buildAuthenticateVirtualHost(options),
					},
				},
			},
			HttpFilters: []*envoy_extensions_filters_network_http_connection_manager_v3.HttpFilter{
				{
					Name: "envoy.filters.http.router",
				},
			},
		})

		li := &envoy_config_listener_v3.Listener{
			Name: fmt.Sprintf("ingress-%d", i),
			FilterChains: []*envoy_config_listener_v3.FilterChain{
				{
					Filters: []*envoy_config_listener_v3.Filter{
						{
							Name: "envoy.filters.network.http_connection_manager",
							ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
								TypedConfig: tc,
							},
						},
					},
				},
			},
		}
		if isInsecure {
			li.Address = buildAddress(addr, 80)
		} else {
			li.Address = buildAddress(addr, 443)
		}
		listeners = append(listeners, li)
	}

	return listeners
}

func (srv *Server) buildAuthenticateVirtualHost(options config.Options) *envoy_config_route_v3.VirtualHost {
	routeToAuthenticate := &envoy_config_route_v3.Route_Route{
		Route: &envoy_config_route_v3.RouteAction{
			ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
				Cluster: "pomerium-authenticate",
			},
		},
	}
	return &envoy_config_route_v3.VirtualHost{
		Name:    "pomerium-authenticate",
		Domains: []string{options.AuthenticateURL.Host},
		Routes: []*envoy_config_route_v3.Route{
			{
				Name: "pomerium-authenticate-path",
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
						Path: "/.pomerium",
					},
				},
				Action: routeToAuthenticate,
			},
			{
				Name: "pomerium-authenticate-prefix",
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
						Prefix: "/.pomerium/",
					},
				},
				Action: routeToAuthenticate,
			},
			{
				Name: "pomerium-authenticate-oauth2-callback",
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
						Path: options.AuthenticateCallbackPath,
					},
				},
				Action: routeToAuthenticate,
			},
		},
	}
}

func (srv *Server) buildClusters(options config.Options) []*envoy_config_cluster_v3.Cluster {
	grpcURL := &url.URL{
		Scheme: "http",
		Host:   srv.GRPCListener.Addr().String(),
	}
	httpURL := &url.URL{
		Scheme: "http",
		Host:   srv.HTTPListener.Addr().String(),
	}

	clusters := []*envoy_config_cluster_v3.Cluster{
		srv.buildCluster("pomerium-control-plane-grpc", grpcURL),
		srv.buildCluster("pomerium-control-plane-http", httpURL),
	}

	if config.IsAuthenticate(options.Services) {
		clusters = append(clusters, srv.buildCluster("pomerium-authenticate", httpURL))
	} else {
		clusters = append(clusters, srv.buildCluster("pomerium-authenticate", options.AuthenticateURL))
	}

	if config.IsAuthorize(options.Services) {
		clusters = append(clusters, srv.buildCluster("pomerium-authorize", grpcURL))
	} else {
		clusters = append(clusters, srv.buildCluster("pomerium-authorize", options.AuthorizeURL))
	}

	if config.IsCache(options.Services) {
		clusters = append(clusters, srv.buildCluster("pomerium-cache", grpcURL))
	} else {
		clusters = append(clusters, srv.buildCluster("pomerium-cache", options.CacheURL))
	}

	return clusters
}

func (srv *Server) buildCluster(name string, endpoint *url.URL) *envoy_config_cluster_v3.Cluster {
	defaultPort := 80
	if endpoint.Scheme == "https" {
		defaultPort = 443
	}
	cluster := &envoy_config_cluster_v3.Cluster{
		Name:                 name,
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STATIC},
		ConnectTimeout:       ptypes.DurationProto(time.Second * 10),
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
				LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{{
					HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
						Endpoint: &envoy_config_endpoint_v3.Endpoint{
							Address: buildAddress(endpoint.Host, defaultPort),
						},
					},
				}},
			}},
		},
		Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{},
	}
	return cluster
}

func buildAddress(hostport string, defaultPort int) *envoy_config_core_v3.Address {
	host, strport, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		strport = fmt.Sprint(defaultPort)
	}
	port, err := strconv.Atoi(strport)
	if err != nil {
		port = defaultPort
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_SocketAddress{SocketAddress: &envoy_config_core_v3.SocketAddress{
			Address:       host,
			PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: uint32(port)},
		}},
	}
}
