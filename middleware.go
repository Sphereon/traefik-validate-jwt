package traefik_validate_jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
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
	TenantIdFilters []TenantIdFilter `json:"filters,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Middleware a Middleware plugin.
type Middleware struct {
	next    http.Handler
	name    string
	filters []TenantIdFilter
}

// New created a new Middleware plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.TenantIdFilters) == 0 {
		return nil, errors.New(fmt.Sprintln("no filters could be found, jwt-validator not created. config:", config))
	}

	m := &Middleware{
		next:    next,
		name:    name,
		filters: config.TenantIdFilters,
	}
	return m, nil
}

func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
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
	}
	tokenString = tokenString[7:]
	fmt.Println("tokenString:", tokenString)

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Get the kid header parameter
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid header parameter")
		}
		fmt.Println("kid:", kid)

		// Get the jwksURL from the idp claim
		jwksURL, ok := m.getJwksUrl(token, ok, "idp")
		if !ok {
			jwksURL, ok = m.getJwksUrl(token, ok, "iss")
			if !ok {
				return nil, fmt.Errorf("could not determine openid-configuration from idp or iss claims")
			}
		}
		fmt.Println("jwksURL:", jwksURL)

		// Get the JSON Web Key Set (JWKS) from the provider's endpoint
		jwksResp, err := http.Get(jwksURL)
		if err != nil {
			return nil, fmt.Errorf("failed to get JWKS from provider's endpoint: %v", err)
		}
		defer jwksResp.Body.Close()

		jwksBody, err := ioutil.ReadAll(jwksResp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read JWKS response body: %v", err)
		}

		var jwks struct {
			Keys []struct {
				Kty string `json:"kty"`
				Kid string `json:"kid"`
				Use string `json:"use"`
				N   string `json:"n"`
				E   string `json:"e"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(jwksBody, &jwks); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JWKS response body: %v", err)
		}

		// Find the matching JSON Web Key (JWK)
		var jwk *jwt.Token
		for _, key := range jwks.Keys {
			if key.Kid == kid && key.Use == "sig" && key.Kty == "RSA" {
				jwk = jwt.New(jwt.GetSigningMethod("RS256"))
				jwk.Header["kid"] = key.Kid
				jwk.Claims = jwt.MapClaims{
					"n": key.N,
					"e": key.E,
				}
				break
			}
		}

		if jwk == nil {
			return nil, fmt.Errorf("matching JWK not found")
		}
		fmt.Println("jwk:", jwk.Claims)

		// Verify the token signature using the JWK
		return jwk.Method.Verify(tokenString, jwk.Signature, jwk.Header["kid"]), nil
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
	if expTime.After(time.Now()) {
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

	fmt.Println("Request authorized")
	m.next.ServeHTTP(rw, req)
}

func (m *Middleware) getJwksUrl(token *jwt.Token, ok bool, claimName string) (string, bool) {
	idp, ok := token.Claims.(jwt.MapClaims)[claimName].(string)
	if !ok {
		return "", false
	}
	jwksURL := fmt.Sprintf("%s/.well-known/openid-configuration", idp)
	return jwksURL, true
}
