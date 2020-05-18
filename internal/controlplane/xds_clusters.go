package controlplane

import (
	"net"
	"net/url"
	"strings"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func (srv *Server) buildClusters(options *config.Options) []*envoy_config_cluster_v3.Cluster {
	grpcURL := &url.URL{
		Scheme: "grpc",
		Host:   srv.GRPCListener.Addr().String(),
	}
	httpURL := &url.URL{
		Scheme: "http",
		Host:   srv.HTTPListener.Addr().String(),
	}
	authzURL := &url.URL{
		Scheme: strings.Replace(options.AuthorizeURL.Scheme, "http", "grpc", -1),
		Host:   options.AuthorizeURL.Host,
	}

	clusters := []*envoy_config_cluster_v3.Cluster{
		srv.buildCluster("pomerium-control-plane-grpc", grpcURL),
		srv.buildCluster("pomerium-control-plane-http", httpURL),
		srv.buildCluster("pomerium-authz", authzURL),
	}

	if config.IsProxy(options.Services) {
		for _, policy := range options.Policies {
			clusters = append(clusters, srv.buildPolicyCluster(&policy))
		}
	}

	return clusters
}

func (srv *Server) buildPolicyCluster(policy *config.Policy) *envoy_config_cluster_v3.Cluster {
	name := getPolicyName(policy)
	defaultPort := 80
	if policy.Destination.Scheme == "https" {
		defaultPort = 443
	}

	cluster := &envoy_config_cluster_v3.Cluster{
		Name:           name,
		ConnectTimeout: ptypes.DurationProto(time.Second * 10),
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
				LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{{
					HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
						Endpoint: &envoy_config_endpoint_v3.Endpoint{
							Address: buildAddress(policy.Destination.Host, defaultPort),
						},
					},
				}},
			}},
		},
		RespectDnsTtl: true,
	}

	if policy.Destination.Scheme == "https" {
		validationContext := &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{}
		if policy.RootCAs != nil {

		} else {
			rootCA, err := getRootCertificateAuthority()
			if err != nil {
				log.Error().Err(err).Msg("unable to enable certificate verification because no root CAs were found")
			} else {
				validationContext.TrustedCa = inlineFilename(rootCA)
				validationContext.MatchSubjectAltNames = []*envoy_type_matcher_v3.StringMatcher{
					{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
							Exact: policy.Destination.Hostname(),
						},
					},
					{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
							Exact: policy.Source.Hostname(),
						},
					},
					{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
							Exact: policy.TLSServerName,
						},
					},
				}
			}
		}

		if policy.TLSSkipVerify {
			validationContext.TrustChainVerification = envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_ACCEPT_UNTRUSTED
		}

		cluster.Http2ProtocolOptions = &envoy_config_core_v3.Http2ProtocolOptions{}
		tlsContext := &envoy_extensions_transport_sockets_tls_v3.UpstreamTlsContext{
			CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
				AlpnProtocols: []string{"h2", "http/1.1"},
				ValidationContextType: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
					ValidationContext: validationContext,
				},
			},
			Sni: policy.Destination.Hostname(),
		}
		if policy.ClientCertificate != nil {
			tlsContext.CommonTlsContext.TlsCertificates = append(tlsContext.CommonTlsContext.TlsCertificates,
				envoyTLSCertificateFromGoTLSCertificate(policy.ClientCertificate))
		}
		if policy.TLSServerName != "" {
			tlsContext.Sni = policy.TLSServerName
		}
		tlsConfig, _ := ptypes.MarshalAny(tlsContext)
		cluster.TransportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "tls",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: tlsConfig,
			},
		}
	}

	if net.ParseIP(urlutil.StripPort(policy.Destination.Host)) == nil {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_LOGICAL_DNS}
	} else {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STATIC}
	}

	return cluster
}

func (srv *Server) buildCluster(name string, endpoint *url.URL) *envoy_config_cluster_v3.Cluster {
	defaultPort := 80
	if endpoint.Scheme == "https" || endpoint.Scheme == "grpcs" {
		defaultPort = 443
	}

	cluster := &envoy_config_cluster_v3.Cluster{
		Name:           name,
		ConnectTimeout: ptypes.DurationProto(time.Second * 10),
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
		RespectDnsTtl: true,
	}

	if endpoint.Scheme == "grpc" {
		cluster.Http2ProtocolOptions = &envoy_config_core_v3.Http2ProtocolOptions{}
	}

	if endpoint.Scheme == "https" || endpoint.Scheme == "grpcs" {
		cluster.TransportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "tls",
		}
	}

	if net.ParseIP(urlutil.StripPort(endpoint.Host)) == nil {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_LOGICAL_DNS}
	} else {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STATIC}
	}

	return cluster
}
