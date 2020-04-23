package controlplane

import (
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/version"
)

func (srv *Server) addHTTPMiddleware() {
	root := srv.HTTPRouter
	root.Use(log.NewHandler(log.Logger))
	root.Use(log.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		log.FromRequest(r).Debug().
			Dur("duration", duration).
			Int("size", size).
			Int("status", status).
			Str("method", r.Method).
			Str("host", r.Host).
			Str("path", r.URL.String()).
			Msg("http-request")
	}))
	root.Use(handlers.RecoveryHandler())

	// if len(o.Headers) != 0 {
	// 	mux.Use(middleware.SetHeaders(o.Headers))
	// }
	root.Use(log.HeadersHandler(httputil.HeadersXForwarded))
	root.Use(log.RemoteAddrHandler("ip"))
	root.Use(log.UserAgentHandler("user_agent"))
	root.Use(log.RefererHandler("referer"))
	root.Use(log.RequestIDHandler("req_id", "Request-Id"))
	root.Use(middleware.Healthcheck("/ping", version.UserAgent()))
	root.HandleFunc("/healthz", httputil.HealthCheck)
	root.HandleFunc("/ping", httputil.HealthCheck)
	root.PathPrefix("/.pomerium/assets/").Handler(http.StripPrefix("/.pomerium/assets/", frontend.MustAssetHandler()))
}

// func (srv *Server) addControlPlaneHTTPRoutes() {
// 	dashboard := srv.HTTPRouter.PathPrefix("/.pomerium").Subrouter()
// 	dashboard.PathPrefix("/assets/").
// 		Handler(http.StripPrefix("/.pomerium/assets/", frontend.MustAssetHandler()))
// 	dashboard.Path("/callback").Handler(http.HandlerFunc(srv.handlePomeriumCallback))
// 	dashboard.Path("/callback/").Handler(http.HandlerFunc(srv.handlePomeriumCallback))
// 	dashboard.Path("/sign_in").Handler(http.HandlerFunc(srv.handlePomeriumSignIn))
// }

// func (srv *Server) handlePomeriumCallback(w http.ResponseWriter, r *http.Request) {
// 	options := srv.currentConfig.Load().(versionedOptions).Options

// 	// first confirm that the url was signed properly
// 	if err := middleware.ValidateRequestURL(r, options.SharedKey); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 	}

// 	redirectURLString := r.FormValue(urlutil.QueryRedirectURI)
// 	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)

// 	if _, err := p.saveCallbackSession(w, r, encryptedSession); err != nil {
// 		return httputil.NewError(http.StatusBadRequest, err)
// 	}
// 	httputil.Redirect(w, r, redirectURLString, http.StatusFound)
// 	return nil
// 	// https://httpbin.localhost.pomerium.io/.pomerium/callback/
// 	// ?pomerium_expiry=1587603017
// 	// &pomerium_issued=1587602717
// 	// &pomerium_redirect_uri=https%3A%2F%2Fhttpbin.localhost.pomerium.io%2F
// 	// &pomerium_session_encrypted=ginSZyI1qTNsHyrsYbXmUoAexpWiXnPP33_b9JTmDGeo-_zUbnFVAAWOIeDLXCciE9CxzUVqRrGqc5mplZ0gU6iMMxTJaSHo_mOJ-QSgLXWlUb0olI0dDjTJoKN0OSDzUxGj4_H-dKljX2lwt1PUKcki3e8XUCn5e6BFrXbIX71TIQm_gsRiYBSu3Ui8pSMwnqezKqenxn2RKY8ItgSJoGlDu2PYcE2tx7So8pEffOPDeXkhvaqqJ-y08YmMh9Lc8clHw9D3ux8dqBbxXXjAiKoreaFUQLVJGjbEy8dChmQRp580KFxlL1Vog4MXbAxVcm5zAKdQQHgpJkYWExoqWlVRysNnx94mVkZ_jM5y0NQHFtIZKE2SdlAjih-aKjAF8p4XiFGSN-wtg8KqADmjxmr3kP5F-oyiefgtGPdmz8-oJQR3vvPUpVYiEdm7Dz3Q1u0C_jCnUNsRcwTxtafEi3-ycU87VM-aZo59IxyKjg7eY-KVt2y5-KOH1rrMtcQN777e2Z8rgRDb9EpqHuOzjcCah9ceJvP1JMDumHDxBIc9w-GpDqEtepUtxV0izhcQLpnFrjM-jc0REWUTF-9_wtfVnZQGAXR-mFFSlrn33ULN7QrW1KrzKDrqCtzEhKxp8oRwzWcejq6ggEq-OPsFmVVPIoQ_UJzWnj1hJEtMXuwM-3lVAJhIdPYwh23bPzEzj8cW5jlTEvPBBB4iUqcDgNfFBIIYEeen08EWV4sfBcfOg2wyALKKG7wj8YNWvFz9F8KOR6SyX2IprqDwUyuoWklqnYCDmtSDFOh-xJezLbHAjfQk8NxMQgvoyqmmueJILaNNRrR8np3necRCS4tLlPF_TQlq
// 	// &pomerium_signature=mUkNquWmElklTI3cUukW_VwooXhcx36xCJKm8MnQ4tY%3D
// }

// func (srv *Server) handlePomeriumSignIn(w http.ResponseWriter, r *http.Request) {
// 	options := srv.currentConfig.Load().(versionedOptions)

// 	// catch a possible infinite redirect loop. The authentication server routes should be matched before these,
// 	// so this shouldn't happen.
// 	if r.Host == options.AuthenticateURL.Host {
// 		http.Error(w, "authentication server route was not matched", http.StatusInternalServerError)
// 		return
// 	}

// 	// sign the URL
// 	signinURL := options.AuthenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/sign_in"})
// 	q := signinURL.Query()
// 	q.Set(urlutil.QueryRedirectURI, r.URL.Query().Get(urlutil.QueryRedirectURI))
// 	signinURL.RawQuery = q.Encode()
// 	redirectTo := urlutil.NewSignedURL(options.SharedKey, signinURL).String()

// 	// finally redirect to the authentication server
// 	http.Redirect(w, r, redirectTo, http.StatusFound)
// }
