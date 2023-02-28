package main

import (
	"context"
	"fmt"
	traefik_validate_jwt "github.com/sanderPostma/traefik-validate-jwt"
	"net/http"
)

// Main
func main() {

	config := traefik_validate_jwt.CreateConfig()
	config.TenantIdFilters = []traefik_validate_jwt.TenantIdFilter{
		{
			TenantId: "e2a42b2f-7460-4499-afc2-425315ef058a",
			AppIds:   []string{"4fc07429-f068-47fa-b5cd-5b460ec8529d"},
		},
	}

	validator, err := traefik_validate_jwt.New(context.Background(), nil, config, "validate-jwt")
	if err != nil {
		panic(fmt.Sprintln("could not create validator", err))
	}

	http.HandleFunc("/", validator.ServeHTTP)
	err = http.ListenAndServe(fmt.Sprintf(":%d", 8112), nil)
	if err != nil {
		panic(fmt.Sprintln("could not listen on port 8112", err))
	}
}
