# gitea-interceptor for Tekton

This a custom gitea interceptor for [tekton triggers](https://github.com/tektoncd/triggers).

The primary function is use the configured webhook secret key to validate payload encryption checksum.

This code borrows from:
- https://github.com/keyporttech/gitea-tekton-interceptor
- https://github.com/tektoncd/triggers/blob/v0.17.1/cmd/interceptors/main.go
- https://github.com/tektoncd/triggers/blob/v0.17.1/pkg/interceptors/server/server.go
- https://github.com/tektoncd/triggers/blob/v0.17.1/pkg/interceptors/github/github.go

## Installation

```sh
kubectl apply -f k8s.yaml
```

## Usage

```yaml
apiVersion: v1
kind: Secret
metadata:
    name: webhook-secret
type: Opaque
stringData:
    # openssl rand -base64 24
    sharedSecret: AZERTYUIOPazertyuiop01234567890=
---
apiVersion: triggers.tekton.dev/v1beta1
kind: Trigger
metadata:
  name: trigger
spec:
  interceptors:
  - name: gitea
    ref:
      name: gitea
      kind: ClusterInterceptor
      apiVersion: triggers.tekton.dev
    params:
    - name: secretRef
      value:
        secretName: webhook-secret
        secretKey: sharedSecret
    - name: eventTypes
      value: ["push"]

[...]
```
