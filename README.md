# authentication-server

## Container image

Every green CI run on `main` publishes `ghcr.io/huseinj/authentication-server` with the tags `latest`,
`sha-<commit>` and `main-<short-sha>-<unix-timestamp>`. The last one is meant for Flux image automation:

```yaml
apiVersion: image.toolkit.fluxcd.io/v1
kind: ImagePolicy
metadata:
  name: authentication-server
spec:
  imageRepositoryRef:
    name: authentication-server
  filterTags:
    pattern: '^main-[a-f0-9]+-(?P<ts>[0-9]+)$'
    extract: '$ts'
  policy:
    numerical:
      order: asc
```
