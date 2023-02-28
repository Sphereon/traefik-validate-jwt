--- UNDER CONSTRUCTION ---

## JWT bearer token validator
Traefik middleware, to authenticate against Azure app registrations.
It filters access be tenant id and application/clientid which have to be in the dynamic configuration.  
(Similar plugins have role checking, but since any Azure tenant can create its own valid JWT containing any role, this one is using the ids as the filter.)

The open-id configuration is deduced from the idp or idd claims. In the openId configuration it will lookup the "jwks_uri" which is then validated against the authentication server.
Next the token expiry time is verified and finally the filters are matched from the config to see if the tenant id and application/clientid is allowed into the target service.
The request is forwarded if all the criteria match.

