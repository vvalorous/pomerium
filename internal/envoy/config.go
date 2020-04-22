package envoy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/envoy/envoyconfig"
)

const (
	defaultAddr = ":443"
)

// GetBootstrapConfig gets the envoy bootstrap config for the given pomerium options.
func GetBootstrapConfig(options *config.Options) *envoyconfig.Bootstrap {
	return &envoyconfig.Bootstrap{
		StaticResources: &envoyconfig.StaticResources{
			Listeners: getListenersConfig(options),
			Clusters:  getClustersConfig(options),
		},
	}
}

func getAbsoluteFilePath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	wd, _ := os.Getwd()
	return filepath.Join(wd, filename)
}

func getListenersConfig(options *config.Options) []envoyconfig.Listener {
	addr := options.Addr
	if addr == "" {
		addr = defaultAddr
	}
	envoyAddr := getAddressFromString(addr, 0)
	var transportSocket *envoyconfig.TransportSocket
	if !options.InsecureServer {
		var cert envoyconfig.TLSCertificate
		if options.Cert != "" {
			cert.CertificateChain = &envoyconfig.DataSource{InlineString: options.Cert}
		} else {
			cert.CertificateChain = &envoyconfig.DataSource{Filename: getAbsoluteFilePath(options.CertFile)}
		}
		if options.Key != "" {
			cert.PrivateKey = &envoyconfig.DataSource{InlineString: options.Key}
		} else {
			cert.PrivateKey = &envoyconfig.DataSource{Filename: getAbsoluteFilePath(options.KeyFile)}
		}
		transportSocket = &envoyconfig.TransportSocket{
			Name: "tls",
			TypedConfig: &envoyconfig.DownstreamTLSContext{
				CommonTLSContext: envoyconfig.CommonTLSContext{
					TLSCertificates: []envoyconfig.TLSCertificate{cert},
				},
			},
		}
	}

	return []envoyconfig.Listener{
		{
			Address: envoyAddr,
			FilterChains: []envoyconfig.FilterChain{{
				Filters: []envoyconfig.Filter{{
					Name: "envoy.filters.network.http_connection_manager",
					TypedConfig: envoyconfig.HTTPConnectionManager{
						StatPrefix: "ingress_http",
						CodecType:  "AUTO",
						RouteConfiguration: envoyconfig.RouteConfiguration{
							Name: "main_route",
							VirtualHosts: append([]envoyconfig.VirtualHost{
								getVirtualHost("pomerium-authentication", options.AuthenticateURL),
								getVirtualHost("pomerium-authorization", options.AuthorizeURL),
							}, getPolicyVirtualHosts(options.Policies)...),
						},
						HTTPFilters: []envoyconfig.HTTPFilter{
							{
								Name: "envoy.filters.http.ext_authz",
								TypedConfig: &envoyconfig.ExtAuthz{
									GRPCService: &envoyconfig.GRPCService{
										EnvoyGRPC: &envoyconfig.EnvoyGRPC{
											ClusterName: "pomerium-authorization",
										},
									},
								},
							},
							{
								Name: "envoy.filters.http.router",
							},
						},
					},
				}},
				TransportSocket: transportSocket,
			}},
		},
	}
}

func getVirtualHost(name string, u *url.URL) envoyconfig.VirtualHost {
	return envoyconfig.VirtualHost{
		Name:    u.Host,
		Domains: []string{u.Host},
		Routes: []envoyconfig.Route{{
			Name: name + "-route",
			Match: envoyconfig.RouteMatch{
				Prefix: "/",
			},
			Route: envoyconfig.RouteAction{
				Cluster: name,
			},
		}},
	}
}

func getPolicyVirtualHosts(policies []config.Policy) []envoyconfig.VirtualHost {
	byHostName := map[string][]config.Policy{}
	for _, policy := range policies {
		byHostName[policy.Source.Host] = append(byHostName[policy.Source.Host], policy)
	}
	var hostnames []string
	for hostname := range byHostName {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)

	var vhs []envoyconfig.VirtualHost
	for _, hostname := range hostnames {
		vh := envoyconfig.VirtualHost{
			Name:    hostname,
			Domains: []string{hostname},
			Routes: []envoyconfig.Route{ // always send /.pomerium/ URLs to the control plane
				{
					Name:  "route-pomerium-prefix",
					Match: envoyconfig.RouteMatch{Prefix: "/.pomerium/"},
					Route: envoyconfig.RouteAction{Cluster: "pomerium-control"},
				},
				{
					Name:  "route-pomerium-path",
					Match: envoyconfig.RouteMatch{Path: "/.pomerium"},
					Route: envoyconfig.RouteAction{Cluster: "pomerium-control"},
				},
			},
		}
		for i, policy := range byHostName[hostname] {
			rm := envoyconfig.RouteMatch{
				Prefix: policy.Prefix,
				Path:   policy.Path,
				Regex:  policy.Regex,
			}
			// one of these must be set, so default to prefix=/
			if rm.Prefix == "" && rm.Path == "" && rm.Regex == "" {
				rm.Prefix = "/"
			}
			r := envoyconfig.Route{
				Name:  fmt.Sprintf("route-%d", i),
				Match: rm,
				Route: envoyconfig.RouteAction{
					Cluster:         getClusterName(policy.Destination.Scheme, policy.Destination.Host),
					PrefixRewrite:   policy.Destination.Path,
					AutoHostRewrite: true,
				},
			}
			vh.Routes = append(vh.Routes, r)
		}
		vhs = append(vhs, vh)
	}

	return vhs
}

func getClusterName(scheme, host string) string {
	return scheme + "-" + host
}

func getClustersConfig(options *config.Options) []envoyconfig.Cluster {
	authenticateURL := options.AuthenticateURL
	if config.IsAuthenticate(options.Services) {
		authenticateURL, _ = url.Parse("https://127.0.0.1:5080")
	}

	authorizeURL := options.AuthorizeURL
	if config.IsAuthorize(options.Services) {
		authorizeURL, _ = url.Parse("http://127.0.0.1:5443")
	}

	cacheURL := options.CacheURL
	if config.IsCache(options.Services) {
		cacheURL, _ = url.Parse("http://127.0.0.1:5443")
	}

	controlURL, _ := url.Parse("https://127.0.0.1:5080")

	clusters := []envoyconfig.Cluster{
		getServiceClusterConfig("pomerium-authentication", authenticateURL),
		getServiceClusterConfig("pomerium-authorization", authorizeURL),
		getServiceClusterConfig("pomerium-cache", cacheURL),
		getServiceClusterConfig("pomerium-control", controlURL),
	}
	clusters = append(clusters, getPoliciesClustersConfig(options.Policies)...)
	return clusters
}

func getServiceClusterConfig(name string, u *url.URL) envoyconfig.Cluster {
	cluster := envoyconfig.Cluster{
		Name:           name,
		ConnectTimeout: "30s",
		LoadAssignment: envoyconfig.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []envoyconfig.LocalityLBEndpoint{{
				LBEndpoints: []envoyconfig.LBEndpoint{{
					Endpoint: envoyconfig.Endpoint{
						Address: getAddressFromString(u.Host, getDefaultPort(u.Scheme)),
					},
				}},
			}},
		},
		HTTP2ProtocolOptions: &envoyconfig.HTTP2ProtocolOptions{},
	}
	host, _, _ := net.SplitHostPort(u.Host)
	if host == "127.0.0.1" {
		cluster.Type = envoyconfig.ClusterDiscoveryTypeStatic
	} else {
		cluster.Type = envoyconfig.ClusterDiscoveryTypeLogicalDNS
	}
	if u.Scheme == "https" {
		cluster.TransportSocket = &envoyconfig.TransportSocket{Name: "tls"}
	}
	return cluster
}

func getPoliciesClustersConfig(policies []config.Policy) []envoyconfig.Cluster {
	type Dst struct {
		Scheme, Host string
	}
	m := map[Dst]struct{}{}
	for _, policy := range policies {
		m[Dst{
			Scheme: policy.Destination.Scheme,
			Host:   policy.Destination.Host,
		}] = struct{}{}
	}
	var dsts []Dst
	for dst := range m {
		dsts = append(dsts, dst)
	}
	sort.Slice(dsts, func(i, j int) bool {
		return (dsts[i].Scheme + "-" + dsts[i].Host) < (dsts[j].Scheme + "-" + dsts[j].Host)
	})

	var clusters []envoyconfig.Cluster
	for _, dst := range dsts {
		c := envoyconfig.Cluster{
			Name:           getClusterName(dst.Scheme, dst.Host),
			Type:           envoyconfig.ClusterDiscoveryTypeLogicalDNS,
			ConnectTimeout: "30s",
			LoadAssignment: envoyconfig.ClusterLoadAssignment{
				ClusterName: getClusterName(dst.Scheme, dst.Host),
				Endpoints: []envoyconfig.LocalityLBEndpoint{{
					LBEndpoints: []envoyconfig.LBEndpoint{{
						Endpoint: envoyconfig.Endpoint{
							Address: getAddressFromString(dst.Host, getDefaultPort(dst.Scheme)),
						},
					}},
				}},
			},
		}
		clusters = append(clusters, c)
	}
	return clusters
}

func getDefaultPort(scheme string) int {
	switch scheme {
	case "https":
		return 443
	}
	return 80
}

func getAddressFromString(addr string, defaultPort int) envoyconfig.Address {
	host, strport, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		strport = fmt.Sprint(defaultPort)
	}
	port, err := strconv.Atoi(strport)
	if err != nil {
		port = defaultPort
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return envoyconfig.Address{
		SocketAddress: &envoyconfig.SocketAddress{
			Address:   host,
			PortValue: &port,
		},
	}
}
