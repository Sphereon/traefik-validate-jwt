## JWT bearer token validator
Traefik middleware, to authenticate against Azure app registrations.
It filters access by tenant id and application/clientid which have to be in the dynamic configuration.  
(Similar plugins have role checking, but since any Azure tenant can create its own valid JWT containing any role, this one is using the ids as the filter.)

The open-id configuration is deduced from the idp or idd claims. In the openId configuration it will look up the "jwks_uri" which is then validated against the authentication server.
Next the token expiry time is verified and finally the filters are matched from the config to see if the tenant id and application/clientid is allowed into the target service.
The request is forwarded if all the criteria match.

The activate the plugin add the following to your Traefik arguments:
```
  - "--experimental.plugins.traefik-validate-jwt.modulename=github.com/sphereon/traefik-validate-jwt"
  - "--experimental.plugins.traefik-validate-jwt.version=v0.1.2"
```

To activate the middleware in a deployment:
```
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: validatejwt
  namespace: my-namespace
spec:
  plugin:
    traefik-validate-jwt:
      TenantIdFilters:
      - AppIds:
        - <app / client uuid>
        TenantId: <tenant uuid>

---

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  namespace: my-namespace
  annotations:
   traefik.ingress.kubernetes.io/router.middlewares: "my-namespace-validatejwt@kubernetescrd"
...
```
