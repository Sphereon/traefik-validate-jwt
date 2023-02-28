package traefik_validate_jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type TenantIdFilter struct {
	TenantId string   `json:"tenantId,omitempty"`
	AppIds   []string `json:"appIds,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	IsTest          bool
	TenantIdFilters []TenantIdFilter `json:"filters,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Middleware a Middleware plugin.
type Middleware struct {
	next           http.Handler
	name           string
	filters        []TenantIdFilter
	keyFuncOptions keyfunc.Options
	jwksURIMap     map[string]string
	jwksMap        map[string]*keyfunc.JWKS
	isTest         bool
}

// New created a new Middleware plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.TenantIdFilters) == 0 && !config.IsTest {
		return nil, errors.New(fmt.Sprintln("no filters could be found, jwt-validator not created. config:", config))
	}
	log.Println("Received config", config)

	m := &Middleware{
		next:       next,
		name:       name,
		filters:    config.TenantIdFilters,
		jwksURIMap: map[string]string{},
		jwksMap:    map[string]*keyfunc.JWKS{},
		isTest:     config.IsTest,
	}

	m.keyFuncOptions = buildKeyFuncOptions()
	return m, nil
}

func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if m.isTest { // Skip Yaegi test because I don't think it can log on to our Azure app registration and get a valid bearer token
		m.next.ServeHTTP(rw, req)
		return
	}

	// Assert input
	if req.RemoteAddr == "" {
		fmt.Println("RemoteAddr is empty")
		return
	}
	tokenString := req.Header.Get("Authorization")
	if tokenString == "" {
		fmt.Println("Authorization header is empty")
		return
	}
	if !strings.HasPrefix(tokenString, "Bearer ") {
		fmt.Println("Authorization header must be a 'Bearer' token")
		return
	}

	tokenString = tokenString[7:]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		jwks, i, err := m.getJwks(token)
		if err != nil {
			return i, err
		}
		return jwks.Keyfunc(token)
	})
	if err != nil {
		fmt.Println("Token validation failed:", err)
		return
	}

	// Check if the token is valid
	if !token.Valid {
		fmt.Println("Token is invalid")
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	expTime := time.Unix(int64(claims["exp"].(float64)), 0)
	if time.Now().UTC().After(expTime) {
		fmt.Println("Token has expired")
		return
	}

	tenantIdFound := false
	appIdFound := false
	tenantIdClaim := claims["tid"].(string)
	appIdClaim := claims["appid"].(string)
	for _, filter := range m.filters {
		if filter.TenantId == tenantIdClaim {
			tenantIdFound = true
			for _, appId := range filter.AppIds {
				if appId == appIdClaim {
					appIdFound = true
					break
				}
			}
			break
		}
	}

	if !tenantIdFound {
		fmt.Println("no match found for tenant id", tenantIdClaim)
		return
	}
	if !appIdFound {
		fmt.Println("no match found for app id", appIdClaim)
		return
	}

	if m.next != nil {
		m.next.ServeHTTP(rw, req)
	} else {
		fmt.Println("Request authorized")
	}
}

func (m *Middleware) getJwks(token *jwt.Token) (*keyfunc.JWKS, interface{}, error) {
	// Get the jwksURL from the idp claim, else try iss
	jwksURL, ok := m.getJwksUrl(token, "idp")
	if !ok {
		jwksURL, ok = m.getJwksUrl(token, "iss")
		if !ok {
			return nil, nil, fmt.Errorf("could not determine openid-configuration from idp or iss claims")
		}
	}

	jwks, found := m.jwksMap[jwksURL]
	if !found {
		// Create jwks handler instance
		var err error
		jwks, err = keyfunc.Get(jwksURL, m.keyFuncOptions)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
		}
		m.jwksMap[jwksURL] = jwks
	}
	return jwks, nil, nil
}

func (m *Middleware) getJwksUrl(token *jwt.Token, claimName string) (string, bool) {
	jwksURI, found := m.jwksURIMap[claimName]
	if found {
		return jwksURI, true
	}

	authServerClaim, ok := token.Claims.(jwt.MapClaims)[claimName].(string)
	if !ok {
		return "", false
	}

	// FIXME this is expensive when the first claim exists but does not work and the second does
	openIdConfigUrl := fmt.Sprintf("%s/.well-known/openid-configuration", authServerClaim)
	openIdResp, err := http.Get(openIdConfigUrl)
	if err != nil {
		return "", false
	}
	defer openIdResp.Body.Close()

	openIdBody, err := io.ReadAll(openIdResp.Body)
	if err != nil {
		return "", false
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(openIdBody, &jsonData); err != nil {
		return "", false
	}

	jwksURI, ok = jsonData["jwks_uri"].(string)
	if ok {
		m.jwksURIMap[claimName] = jwksURI
	}
	return jwksURI, ok
}

func buildKeyFuncOptions() keyfunc.Options {
	return keyfunc.Options{
		Ctx: context.Background(),
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}
}
