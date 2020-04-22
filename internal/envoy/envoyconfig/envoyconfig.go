package envoyconfig

import (
	"encoding/json"
	"time"
)

type ClusterDiscoveryType string

const (
	ClusterDiscoveryTypeStatic              ClusterDiscoveryType = "STATIC"
	ClusterDiscoveryTypeStrictDNS           ClusterDiscoveryType = "STRICT_DNS"
	ClusterDiscoveryTypeLogicalDNS          ClusterDiscoveryType = "LOGICAL_DNS"
	ClusterDiscoveryTypeEDS                 ClusterDiscoveryType = "EDS"
	ClusterDiscoveryTypeOriginalDestination ClusterDiscoveryType = "ORIGINAL_DST"
)

type (
	Address struct {
		SocketAddress *SocketAddress `json:"socket_address,omitempty"`
		Pipe          *Pipe          `json:"pipe,omitempty"`
	}
	Bootstrap struct {
		StaticResources *StaticResources `json:"static_resources,omitempty"`
	}
	CIDRRange struct {
	}
	Cluster struct {
		Name                 string                `json:"name"`
		Type                 ClusterDiscoveryType  `json:"type"`
		ConnectTimeout       string                `json:"connect_timeout,omitempty"`
		LoadAssignment       ClusterLoadAssignment `json:"load_assignment"`
		HTTP2ProtocolOptions *HTTP2ProtocolOptions `json:"http2_protocol_options,omitempty"`
		TransportSocket      *TransportSocket      `json:"transport_socket,omitempty"`
	}
	ClusterLoadAssignment struct {
		ClusterName string                       `json:"cluster_name"`
		Endpoints   []LocalityLBEndpoint         `json:"endpoints"`
		Policy      *ClusterLoadAssignmentPolicy `json:"policy,omitempty"`
	}
	ClusterLoadAssignmentPolicy struct {
	}
	Endpoint struct {
		Address           Address            `json:"address"`
		HealthCheckConfig *HealthCheckConfig `json:"health_check_config,omitempty"`
		Hostname          string             `json:"hostname,omitempty"`
	}
	Filter struct {
		Name        string      `json:"name"`
		Config      interface{} `json:"config,omitempty"`
		TypedConfig interface{} `json:"typed_config,omitempty"`
	}
	FilterChain struct {
		FilterChainMatch FilterChainMatch `json:"filter_chain_match"`
		Filters          []Filter         `json:"filters"`
		UseProxyProtocol bool             `json:"use_proxy_protocol,omitempty"`
		TransportSocket  *TransportSocket `json:"transport_socket,omitempty"`
	}
	FilterChainMatch struct {
		DestinationPort      *uint32     `json:"destination_port,omitempty"`
		PrefixRanges         []CIDRRange `json:"prefix_ranges,omitempty"`
		SourceType           string      `json:"source_type,omitempty"`
		SourcePrefixRanges   []CIDRRange `json:"source_prefix_ranges,omitempty"`
		SourcePorts          []uint32    `json:"source_ports,omitempty"`
		ServerNames          []string    `json:"server_names,omitempty"`
		TransportProtocol    string      `json:"transport_protocol,omitempty"`
		ApplicationProtocols []string    `json:"application_protocols,omitempty"`
	}
	HealthCheckConfig struct {
	}
	HealthStatus struct {
	}
	HTTP2ProtocolOptions struct {
	}
	LBEndpoint struct {
		Endpoint            Endpoint      `json:"endpoint"`
		HealthStatus        *HealthStatus `json:"health_status,omitempty"`
		Metadata            *Metadata     `json:"metadata,omitempty"`
		LoadBalancingWeight *uint32       `json:"load_balancing_weight,omitempty"`
	}
	Listener struct {
		Name         string        `json:"name,omitempty"`
		Address      Address       `json:"address,omitempty"`
		FilterChains []FilterChain `json:"filter_chains"`
	}
	Locality struct {
		Region  string `json:"region,omitempty"`
		Zone    string `json:"zone,omitempty"`
		SubZone string `json:"sub_zone,omitempty"`
	}
	LocalityLBEndpoint struct {
		Locality            *Locality    `json:"locality,omitempty"`
		LBEndpoints         []LBEndpoint `json:"lb_endpoints"`
		LoadBalancingWeight *uint32      `json:"load_balancing_weight,omitempty"`
		Priority            uint32       `json:"priority,omitempty"`
	}
	Metadata struct {
	}
	Pipe struct {
		Path string `json:"path"`
		Mode uint32 `json:"mode"`
	}
	SocketAddress struct {
		Protocol     string `json:"protocol,omitempty"`
		Address      string `json:"address"`
		PortValue    *int   `json:"port_value,omitempty"`
		NamedPort    string `json:"named_port,omitempty"`
		ResolverName string `json:"resolver_name,omitempty"`
	}
	StaticResources struct {
		Listeners []Listener `json:"listeners,omitempty"`
		Clusters  []Cluster  `json:"clusters,omitempty"`
	}
	TransportSocket struct {
		Name        string      `json:"name"`
		TypedConfig interface{} `json:"typed_config"`
	}
)

type (
	DownstreamTLSContext struct {
		CommonTLSContext CommonTLSContext `json:"common_tls_context"`
	}
	CommonTLSContext struct {
		TLSCertificates []TLSCertificate `json:"tls_certificates"`
	}
	TLSCertificate struct {
		CertificateChain *DataSource `json:"certificate_chain,omitempty"`
		PrivateKey       *DataSource `json:"private_key,omitempty"`
	}
	DataSource struct {
		Filename     string `json:"filename,omitempty"`
		InlineBytes  []byte `json:"inline_bytes,omitempty"`
		InlineString string `json:"inline_string,omitempty"`
	}
)

func (dtlsctx DownstreamTLSContext) MarshalJSON() ([]byte, error) {
	type noncustom DownstreamTLSContext
	return json.Marshal(struct {
		noncustom
		Type string `json:"@type"`
	}{
		noncustom: noncustom(dtlsctx),
		Type:      "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
	})
}

type (
	AccessLog struct {
		Name        string           `json:"name"`
		Filter      *AccessLogFilter `json:"filter"`
		TypedConfig interface{}      `json:"typed_config"`
	}
	AccessLogFilter struct {
	}
	FileAccessLog struct {
		Path string `json:"path"`
	}
	HTTPConnectionManager struct {
		StatPrefix         string             `json:"stat_prefix"`
		CodecType          string             `json:"codec_type"`
		RouteConfiguration RouteConfiguration `json:"route_config"`
		HTTPFilters        []HTTPFilter       `json:"http_filters,omitempty"`
		AccessLog          []AccessLog        `json:"access_log"`
	}
	HTTPFilter struct {
		Name        string      `json:"name"`
		TypedConfig interface{} `json:"typed_config"`
	}
	Route struct {
		Name  string      `json:"name"`
		Match RouteMatch  `json:"match"`
		Route RouteAction `json:"route"`
	}
	RouteAction struct {
		Cluster         string `json:"cluster"`
		PrefixRewrite   string `json:"prefix_rewrite"`
		AutoHostRewrite bool   `json:"auto_host_rewrite"`
	}
	RouteMatch struct {
		Prefix string `json:"prefix,omitempty"`
		Path   string `json:"path,omitempty"`
		Regex  string `json:"regex,omitempty"`
	}
	RouteConfiguration struct {
		Name         string        `json:"name"`
		VirtualHosts []VirtualHost `json:"virtual_hosts"`
	}
	VirtualHost struct {
		Name    string   `json:"name"`
		Domains []string `json:"domains"`
		Routes  []Route  `json:"routes"`
	}
)

func (fal FileAccessLog) MarshalJSON() ([]byte, error) {
	type noncustom FileAccessLog
	return json.Marshal(struct {
		noncustom
		Type string `json:"@type"`
	}{
		noncustom: noncustom(fal),
		Type:      "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
	})
}

func (mgr HTTPConnectionManager) MarshalJSON() ([]byte, error) {
	type noncustom HTTPConnectionManager
	return json.Marshal(struct {
		noncustom
		Type string `json:"@type"`
	}{
		noncustom: noncustom(mgr),
		Type:      "type.googleapis.com/envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager",
	})
}

type (
	ExtAuthz struct {
		GRPCService *GRPCService `json:"grpc_service,omitempty"`
	}
	GRPCService struct {
		EnvoyGRPC *EnvoyGRPC    `json:"envoy_grpc,omitempty"`
		Timeout   time.Duration `json:"timeout,omitempty"`
	}
	EnvoyGRPC struct {
		ClusterName string `json:"cluster_name"`
	}
)

func (extauthz ExtAuthz) MarshalJSON() ([]byte, error) {
	type noncustom ExtAuthz
	return json.Marshal(struct {
		noncustom
		Type string `json:"@type"`
	}{
		noncustom: noncustom(extauthz),
		Type:      "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
	})
}
