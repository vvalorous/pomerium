// Package cluster contains the configuration for setting up the cluster used for integration tests.
//
package cluster

import (
	"fmt"
	"net"
	"strconv"

	"github.com/pomerium/pomerium/config"
)

// ReferenceOpenIDProviderURL is the URL to use for the reference openid provider.
const ReferenceOpenIDProviderURL = "https://reference-openid-provider.herokuapp.com"

// An Endpoint represents a logical endpoint in a cluster. It may be frontend with a proxy, or the actual backend, depending on the port.
type Endpoint int

// Endpoints
const (
	EndpointPomeriumAuthenticate Endpoint = iota
	EndpointPomeriumAuthorize
	EndpointPomeriumCache
	EndpointPomeriumProxy
	EndpointHTTPDetailsTrusted
	EndpointHTTPDetailsTrustedMTLS
	EndpointHTTPDetailsUntrusted
	EndpointHTTPDetailsWronglyNamed
	EndpointWSEcho
)

var endpointToUpstreamPort = map[Endpoint]int{
	EndpointHTTPDetailsTrusted:      9100,
	EndpointHTTPDetailsTrustedMTLS:  9101,
	EndpointHTTPDetailsUntrusted:    9102,
	EndpointHTTPDetailsWronglyNamed: 9103,
	EndpointWSEcho:                  9105,
}

var endpointToSubdomain = map[Endpoint]string{
	EndpointPomeriumAuthenticate:    "authenticate",
	EndpointPomeriumAuthorize:       "authorize",
	EndpointPomeriumCache:           "cache",
	EndpointHTTPDetailsTrusted:      "httpdetails",
	EndpointHTTPDetailsTrustedMTLS:  "mtls-httpdetails",
	EndpointHTTPDetailsUntrusted:    "untrusted-httpdetails",
	EndpointHTTPDetailsWronglyNamed: "wrongly-named-httpdetails",
	EndpointWSEcho:                  "ws-echo",
}

// UpstreamPort returns the upstream port for the given endpoint.
func (e Endpoint) UpstreamPort() int {
	return endpointToUpstreamPort[e]
}

// Hostname returns the hostname for the given endpoint.
func (e Endpoint) Hostname() string {
	return endpointToSubdomain[e] + ".localhost.pomerium.io"
}

// Proxy represents a proxy cluster.
type Proxy int

// Proxies
const (
	ProxyAllInOne Proxy = iota
	ProxySecure
	ProxyInsecure
)

var proxyToString = map[Proxy]string{
	ProxyAllInOne: "all-in-one",
	ProxySecure:   "secure",
	ProxyInsecure: "insecure",
}

var proxyPorts = map[Proxy]map[Endpoint]int{
	ProxyAllInOne: {
		EndpointPomeriumAuthenticate: 9000,
		EndpointPomeriumAuthorize:    9001,
		EndpointPomeriumCache:        9001,
		EndpointPomeriumProxy:        9000,
	},
	ProxySecure: {
		EndpointPomeriumAuthenticate: 9010,
		EndpointPomeriumAuthorize:    9011,
		EndpointPomeriumCache:        9012,
		EndpointPomeriumProxy:        9013,
	},
	ProxyInsecure: {
		EndpointPomeriumAuthenticate: 9020,
		EndpointPomeriumAuthorize:    9021,
		EndpointPomeriumCache:        9022,
		EndpointPomeriumProxy:        9023,
	},
}

var proxyToScheme = map[Proxy]map[Endpoint]string{
	ProxyAllInOne: {
		EndpointPomeriumAuthenticate: "https",
		EndpointPomeriumAuthorize:    "http",
		EndpointPomeriumCache:        "http",
		EndpointPomeriumProxy:        "https",
	},
}

// DownstreamPort returns the port for the given endpoint using this proxy.
func (p Proxy) DownstreamPort(endpoint Endpoint) int {
	if port, ok := proxyPorts[p][endpoint]; ok {
		return port
	}
	// default to the pomerium proxy port so that pomerium handles it
	return proxyPorts[p][EndpointPomeriumProxy]
}

// DownstreamURL returns the URL for the given endpoint using this proxy.
func (p Proxy) DownstreamURL(endpoint Endpoint) string {
	return fmt.Sprintf("%s://%s:%d", p.Scheme(endpoint), endpoint.Hostname(), p.DownstreamPort(endpoint))
}

// Scheme returns the scheme for the given endpoint using this proxy.
func (p Proxy) Scheme(endpoint Endpoint) string {
	if scheme, ok := proxyToScheme[p][endpoint]; ok {
		return scheme
	}
	// default to the pomerium proxy scheme so that pomerium handles it
	return proxyToScheme[p][EndpointPomeriumProxy]
}

// String returns the proxy's name.
func (p Proxy) String() string {
	return proxyToString[p]
}

// UpstreamPort returns the port for the given endpoint using this proxy.
func (p Proxy) UpstreamPort(endpoint Endpoint) int {
	if port, ok := proxyPorts[p][endpoint]; ok {
		return port
	}
	return endpoint.UpstreamPort()
}

// UpstreamURL returns the URL for the given endpoint using this proxy.
func (p Proxy) UpstreamURL(endpoint Endpoint) string {
	return fmt.Sprintf("%s://%s:%d", p.Scheme(endpoint), endpoint.Hostname(), p.UpstreamPort(endpoint))
}

// GetPomeriumConfigs returns pomerium configurations for each of the pomerium services needed for this proxy.
func (p Proxy) GetPomeriumConfigs(base *config.Options) []*config.Options {
	var options []*config.Options

	type ServiceDefinition struct {
		Name         string
		Addr         string
		GRPCAddr     string
		GRPCInsecure bool
	}

	var serviceDefinitions []ServiceDefinition
	if p == ProxyAllInOne {
		serviceDefinitions = append(serviceDefinitions,
			ServiceDefinition{
				Name:         "all",
				Addr:         net.JoinHostPort("", strconv.Itoa(p.DownstreamPort(EndpointPomeriumProxy))),
				GRPCAddr:     net.JoinHostPort("", strconv.Itoa(p.DownstreamPort(EndpointPomeriumAuthorize))),
				GRPCInsecure: true,
			})
	} else {
		serviceDefinitions = append(serviceDefinitions,
			ServiceDefinition{
				Name: "authenticate",
				Addr: net.JoinHostPort("", strconv.Itoa(p.DownstreamPort(EndpointPomeriumAuthenticate))),
			},
			ServiceDefinition{
				Name:         "authorize",
				GRPCAddr:     net.JoinHostPort("", strconv.Itoa(p.DownstreamPort(EndpointPomeriumAuthorize))),
				GRPCInsecure: p.Scheme(EndpointPomeriumAuthorize) == "http",
			},
			ServiceDefinition{
				Name:         "cache",
				GRPCAddr:     net.JoinHostPort("", strconv.Itoa(p.DownstreamPort(EndpointPomeriumCache))),
				GRPCInsecure: p.Scheme(EndpointPomeriumCache) == "http",
			},
			ServiceDefinition{
				Name: "proxy",
				Addr: net.JoinHostPort("", strconv.Itoa(p.DownstreamPort(EndpointPomeriumProxy))),
			},
		)
	}

	for _, serviceDefinition := range serviceDefinitions {
		o := new(config.Options)
		*o = *base

		o.Services = serviceDefinition.Name
		o.Addr = serviceDefinition.Addr
		o.GRPCAddr = serviceDefinition.GRPCAddr
		o.GRPCInsecure = serviceDefinition.GRPCInsecure
		o.AuthenticateURLString = p.DownstreamURL(EndpointPomeriumAuthenticate)
		o.ProviderURL = ReferenceOpenIDProviderURL
		o.AuthorizeURLString = p.UpstreamURL(EndpointPomeriumAuthorize)
		o.CacheURLString = p.UpstreamURL(EndpointPomeriumCache)

		options = append(options, o)
	}

	return options
}
