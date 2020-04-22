//go:generate protoc -I ../internal/grpc/authorize/ --go_out=plugins=grpc:../internal/grpc/authorize/ ../internal/grpc/authorize/authorize.proto

package authorize

import (
	"context"
	"net/url"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type_v2 "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// IsAuthorized checks to see if a given user is authorized to make a request.
func (a *Authorize) IsAuthorized(ctx context.Context, in *authorize.IsAuthorizedRequest) (*authorize.IsAuthorizedReply, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.IsAuthorized")
	defer span.End()

	req := &evaluator.Request{
		User:       in.GetUserToken(),
		Header:     cloneHeaders(in.GetRequestHeaders()),
		Host:       in.GetRequestHost(),
		Method:     in.GetRequestMethod(),
		RequestURI: in.GetRequestRequestUri(),
		RemoteAddr: in.GetRequestRemoteAddr(),
		URL:        getFullURL(in.GetRequestUrl(), in.GetRequestHost()),
	}
	return a.pe.IsAuthorized(ctx, req)
}

const (
	signinPath = "/.pomerium/sign_in"
)

func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v2.CheckRequest) (*envoy_service_auth_v2.CheckResponse, error) {
	// a.mu.RLock()
	// authenticateURL := *a.authenticateURL
	// sharedKey := a.sharedKey
	// a.mu.RUnlock()

	requestURL := getCheckRequestURL(in)
	req := &evaluator.Request{
		Header:     getCheckRequestHeaders(in),
		Host:       in.GetAttributes().GetRequest().GetHttp().GetHost(),
		Method:     in.GetAttributes().GetRequest().GetHttp().GetMethod(),
		RequestURI: requestURL,
		RemoteAddr: in.GetAttributes().GetSource().GetAddress().String(),
		URL:        requestURL,
	}
	reply, err := a.pe.IsAuthorized(ctx, req)
	if err != nil {
		return nil, err
	}

	if reply.Allow {
		return &envoy_service_auth_v2.CheckResponse{
			Status:       &status.Status{Code: int32(codes.OK), Message: "OK"},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{OkResponse: &envoy_service_auth_v2.OkHttpResponse{}},
		}, nil
	}

	// host := in.GetAttributes().GetRequest().GetHttp().GetHost()
	// path := in.GetAttributes().GetRequest().GetHttp().GetPath()

	// signinURL := authenticateURL.ResolveReference(&url.URL{Path: signinPath})
	// q := signinURL.Query()
	// q.Set(urlutil.QueryRedirectURI, "https://"+host+path)
	// signinURL.RawQuery = q.Encode()
	// redirectTo := urlutil.NewSignedURL(sharedKey, signinURL).String()

	return &envoy_service_auth_v2.CheckResponse{
		Status: &status.Status{
			Code:    int32(codes.Unauthenticated),
			Message: "unauthenticated",
		},
		HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
				Status: &envoy_type_v2.HttpStatus{
					Code: envoy_type_v2.StatusCode_Found,
				},
				// Headers: []*envoy_api_v2_core.HeaderValueOption{{
				// 	Header: &envoy_api_v2_core.HeaderValue{
				// 		Key:   "Location",
				// 		Value: redirectTo,
				// 	},
				// }},
			},
		},
	}, nil
}

type protoHeader map[string]*authorize.IsAuthorizedRequest_Headers

func cloneHeaders(in protoHeader) map[string][]string {
	out := make(map[string][]string, len(in))
	for key, values := range in {
		newValues := make([]string, len(values.Value))
		copy(newValues, values.Value)
		out[key] = newValues
	}
	return out
}

func getFullURL(rawurl, host string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		u = &url.URL{Path: rawurl}
	}
	if u.Host == "" {
		u.Host = host
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	return u.String()
}

func getCheckRequestHeaders(req *envoy_service_auth_v2.CheckRequest) map[string][]string {
	h := make(map[string][]string)
	ch := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	if ch != nil {
		for k, v := range ch {
			h[k] = []string{v}
		}
	}
	return h
}

func getCheckRequestURL(req *envoy_service_auth_v2.CheckRequest) string {
	h := req.GetAttributes().GetRequest().GetHttp()
	u := &url.URL{
		Scheme:   h.GetScheme(),
		Host:     h.GetHost(),
		Path:     h.GetPath(),
		RawQuery: h.GetQuery(),
	}
	return u.String()
}
