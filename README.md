
## JWT bearer token validator
Traefik middleware, to authenticate against Azure app registrations.

The open-id configuration is deduced from the idp or idd claims. In the openId configuration it will lookup the "jwks_uri" which is then validated against the authentication server.
Next the token expiry time is verified and finally a filter is matched from the config to see if the tenant id and application/clientid is allowed into the target service.
The request is forwarded if all the criteria match.

--- UNDER CONSTRUCTION ---
