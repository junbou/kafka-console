package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"os"

	"github.com/cloudhut/common/rest"
	"github.com/go-chi/chi/v5"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	pkgconnect "github.com/redpanda-data/console/backend/pkg/connect"
	"github.com/redpanda-data/console/backend/pkg/console"
	"github.com/redpanda-data/console/backend/pkg/redpanda"
	"go.uber.org/zap"
)

type customHooks struct {
	Logger   *zap.Logger
	Username string
	Password string
}

const loginCookieKey string = "_ltc"

func newCustomHooks(logger *zap.Logger) *Hooks {
	d := &customHooks{
		Logger:   logger,
		Username: os.Getenv("CONSOLE_USERNAME"),
		Password: os.Getenv("CONSOLE_PASSWORD"),
	}
	return &Hooks{
		Authorization: d,
		Route:         d,
		Console:       d,
	}
}

// Router Hooks
func (c *customHooks) ConfigAPIRouter(r chi.Router) {
	r.Use(c.CheckLogin)
	r.Get("/api/users/me", c.handleMe())
}
func (*customHooks) ConfigAPIRouterPostRegistration(_ chi.Router) {}
func (*customHooks) ConfigWsRouter(_ chi.Router)                  {}
func (*customHooks) ConfigInternalRouter(_ chi.Router)            {}
func (c *customHooks) ConfigRouter(r chi.Router) {
	r.Get("/auth/providers", c.handleAuthProviders())
	r.Post("/auth/login", c.handleAuthLogin())
	r.Get("/logout", c.handleLogout())
}
func (*customHooks) ConfigGRPCGateway(_ *runtime.ServeMux) {}
func (*customHooks) ConfigConnectRPC(req ConfigConnectRPCRequest) ConfigConnectRPCResponse {
	return ConfigConnectRPCResponse{
		Interceptors:       req.BaseInterceptors,
		AdditionalServices: []ConnectService{},
	}
}

// Authorization Hooks
func (*customHooks) CanSeeTopic(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanCreateTopic(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanEditTopicConfig(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanDeleteTopic(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanPublishTopicRecords(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanDeleteTopicRecords(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanViewTopicPartitions(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanViewTopicConfig(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanViewTopicMessages(_ context.Context, _ *ListMessagesRequest) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanUseMessageSearchFilters(_ context.Context, _ *ListMessagesRequest) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanViewTopicConsumers(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) AllowedTopicActions(_ context.Context, _ string) ([]string, *rest.Error) {
	// "all" will be considered as wild card - all actions are allowed
	return []string{"all"}, nil
}
func (*customHooks) PrintListMessagesAuditLog(_ *http.Request, _ *console.ListMessageRequest) {}
func (*customHooks) CanListACLs(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanCreateACL(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanDeleteACL(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanListQuotas(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanSeeConsumerGroup(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanEditConsumerGroup(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanDeleteConsumerGroup(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) AllowedConsumerGroupActions(_ context.Context, _ string) ([]string, *rest.Error) {
	// "all" will be considered as wild card - all actions are allowed
	return []string{"all"}, nil
}

func (*customHooks) CanPatchPartitionReassignments(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanPatchConfigs(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanViewConnectCluster(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanEditConnectCluster(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanDeleteConnectCluster(_ context.Context, _ string) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) AllowedConnectClusterActions(_ context.Context, _ string) ([]string, *rest.Error) {
	// "all" will be considered as wild card - all actions are allowed
	return []string{"all"}, nil
}

func (*customHooks) CanListKafkaUsers(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanCreateKafkaUsers(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanDeleteKafkaUsers(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) IsProtectedKafkaUser(_ string) bool {
	return false
}

func (*customHooks) CanViewSchemas(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanCreateSchemas(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanDeleteSchemas(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

func (*customHooks) CanManageSchemaRegistry(_ context.Context) (bool, *rest.Error) {
	return true, nil
}

// Console hooks
func (*customHooks) ConsoleLicenseInformation(_ context.Context) redpanda.License {
	return redpanda.License{Source: redpanda.LicenseSourceConsole, Type: redpanda.LicenseTypeOpenSource, ExpiresAt: math.MaxInt32}
}

func (*customHooks) EnabledFeatures() []string {
	return []string{"SINGLE_SIGN_ON", "REASSIGN_PARTITIONS"}
}

func (*customHooks) EndpointCompatibility() []console.EndpointCompatibilityEndpoint {
	return nil
}

func (*customHooks) CheckWebsocketConnection(r *http.Request, _ ListMessagesRequest) (context.Context, error) {
	return r.Context(), nil
}

func (*customHooks) EnabledConnectClusterFeatures(_ context.Context, _ string) []pkgconnect.ClusterFeature {
	return nil
}

// Handlers
func (c *customHooks) handleAuthProviders() http.HandlerFunc {
	type provider struct {
		AuthenticationMethod string `json:"authenticationMethod"`
		DisplayName          string `json:"displayName"`
		Url                  string `json:"url"`
	}
	type response struct {
		Providers  []provider `json:"providers"`
		LoginTitle string     `json:"loginTitle"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		p := &provider{
			AuthenticationMethod: "PLAIN_CREDENTIALS",
			DisplayName:          "Basic",
			Url:                  "/auth/login",
		}
		res := &response{
			Providers:  []provider{*p},
			LoginTitle: "Login",
		}

		rest.SendResponse(w, r, c.Logger, http.StatusOK, res)
	}
}

func (c *customHooks) handleAuthLogin() http.HandlerFunc {
	type loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type response struct {
		Success bool `json:"success"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Parse and validate request
		var req loginRequest
		restErr := rest.Decode(w, r, &req)
		if restErr != nil {
			rest.SendRESTError(w, r, c.Logger, restErr)
			return
		}

		// 2. Check if input is valid
		if req.Username != c.Username || req.Password != c.Password {
			rest.SendRESTError(w, r, c.Logger, &rest.Error{
				Err:      fmt.Errorf("invalid principal"),
				Status:   http.StatusUnauthorized,
				Message:  "Invalid principal",
				IsSilent: false,
			})
			return
		}

		// 3. Send OK
		res := &response{
			Success: true,
		}
		// save username to cookie
		scheme := r.Header.Get("X-Forwarded-Proto")
		if scheme == "" {
			scheme = r.URL.Scheme
		}
		http.SetCookie(w, &http.Cookie{
			Name:     loginCookieKey,
			Value:    req.Username,
			Secure:   scheme == "https",
			HttpOnly: true,
			Path:     "/",
		})
		rest.SendResponse(w, r, c.Logger, http.StatusOK, res)
	}
}

func (c *customHooks) handleLogout() http.HandlerFunc {
	type response struct {
		Success bool `json:"success"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   loginCookieKey,
			Value:  "",
			MaxAge: -1,
		})
		res := &response{
			Success: true,
		}
		rest.SendResponse(w, r, c.Logger, http.StatusOK, res)
	}
}

func (c *customHooks) handleMe() http.HandlerFunc {
	type meta struct {
		Email     string `json:"email"`
		Name      string `json:"name"`
		AvatarUrl string `json:"avatarUrl"`
	}
	type user struct {
		Id                 string `json:"id"`
		InternalIdentifier string `json:"internalIdentifier"`
		ProviderID         int    `json:"providerID"`
		ProviderName       string `json:"providerName"`
		Meta               meta   `json:"meta"`
	}
	type response struct {
		User                    user `json:"user"`
		CanViewConsoleUsers     bool `json:"canViewConsoleUsers"`
		CanListAcls             bool `json:"canListAcls"`
		CanReassignPartitions   bool `json:"canReassignPartitions"`
		CanPatchConfigs         bool `json:"canPatchConfigs"`
		CanViewSchemas          bool `json:"canViewSchemas"`
		CanCreateSchemas        bool `json:"canCreateSchemas"`
		CanDeleteSchemas        bool `json:"canDeleteSchemas"`
		CanManageSchemaRegistry bool `json:"canManageSchemaRegistry"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// get cookie value
		cookie, err := r.Cookie(loginCookieKey)
		if err != nil || cookie.Value != c.Username {
			rest.SendRESTError(w, r, c.Logger, &rest.Error{
				Err:      fmt.Errorf("invalid principal"),
				Status:   http.StatusUnauthorized,
				Message:  "Invalid principal",
				IsSilent: false,
			})
			return
		}
		username := cookie.Value
		res := &response{
			User: user{
				Id:                 username,
				InternalIdentifier: username,
				ProviderID:         -1,
				ProviderName:       "basic",
				Meta: meta{
					Email:     "",
					Name:      username,
					AvatarUrl: "",
				},
			},
			CanViewConsoleUsers:     false,
			CanListAcls:             true,
			CanReassignPartitions:   true,
			CanPatchConfigs:         true,
			CanViewSchemas:          true,
			CanCreateSchemas:        true,
			CanDeleteSchemas:        true,
			CanManageSchemaRegistry: true,
		}
		rest.SendResponse(w, r, c.Logger, http.StatusOK, res)
	}
}

func (c *customHooks) CheckLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(loginCookieKey)
		if err != nil || cookie.Value != c.Username {
			rest.SendRESTError(w, r, c.Logger, &rest.Error{
				Err:      fmt.Errorf("invalid principal"),
				Status:   http.StatusUnauthorized,
				Message:  "Invalid principal",
				IsSilent: false,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
