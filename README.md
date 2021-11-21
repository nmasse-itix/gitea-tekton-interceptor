# gitea-interceptor for Tekton

This a custom gitea interceptor for [tekton triggers](https://github.com/tektoncd/triggers).

The primary function is use the configured webhook secret key to validate payload encryption checksum.

This code borrows from:
- https://github.com/keyporttech/gitea-tekton-interceptor
- https://github.com/tektoncd/triggers/blob/v0.17.1/cmd/interceptors/main.go
- https://github.com/tektoncd/triggers/blob/v0.17.1/pkg/interceptors/server/server.go
- https://github.com/tektoncd/triggers/blob/v0.17.1/pkg/interceptors/github/github.go

