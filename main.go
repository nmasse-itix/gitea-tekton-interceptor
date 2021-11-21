/*
Copyright 2020 The Tekton Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	
	"google.golang.org/grpc/codes"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"
	secretInformer "knative.dev/pkg/client/injection/kube/informers/core/v1/secret"
	"knative.dev/pkg/injection"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/signals"
	triggersv1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	corev1lister "k8s.io/client-go/listers/core/v1"
	"github.com/tektoncd/triggers/pkg/interceptors"
)

const (
	// Port is the port that the port that interceptor service listens on
	Port         = 8080
	readTimeout  = 5 * time.Second
	writeTimeout = 20 * time.Second
	idleTimeout  = 60 * time.Second
)

func main() {
	// set up signals so we handle the first shutdown signal gracefully
	ctx := signals.NewContext()

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to build config: %v", err)
	}

	ctx, startInformer := injection.EnableInjectionOrDie(ctx, clusterConfig)

	zap, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to initialize logger: %s", err)
	}
	logger := zap.Sugar()
	ctx = logging.WithLogger(ctx, logger)
	defer func() {
		if err := logger.Sync(); err != nil {
			log.Fatalf("failed to sync the logger: %s", err)
		}
	}()

	secretLister := secretInformer.Get(ctx).Lister()
	service := NewGiteaInterceptor(secretLister, logger)
	startInformer()

	mux := http.NewServeMux()
	mux.Handle("/", service)
	mux.HandleFunc("/ready", readinessHandler)

	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", Port),
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
		Handler:      mux,
	}

	logger.Infof("Listen and serve on port %d", Port)
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatalf("failed to start interceptors service: %v", err)
	}
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (gi *GiteaInterceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := gi.executeInterceptor(r)
	if err != nil {
		switch e := err.(type) {
		case Error:
			gi.Logger.Infof("HTTP %d - %s", e.Status(), e)
			http.Error(w, e.Error(), e.Status())
		default:
			gi.Logger.Errorf("Non Status Error: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
	w.Header().Add("Content-Type", "application/json")
	if _, err := w.Write(b); err != nil {
		gi.Logger.Errorf("failed to write response: %s", err)
	}
}

// Error represents a handler error. It provides methods for a HTTP status
// code and embeds the built-in error interface.
type Error interface {
	error
	Status() int
}

// HTTPError represents an error with an associated HTTP status code.
type HTTPError struct {
	Code int
	Err  error
}

// Allows HTTPError to satisfy the error interface.
func (se HTTPError) Error() string {
	return se.Err.Error()
}

// Returns our HTTP status code.
func (se HTTPError) Status() int {
	return se.Code
}

func badRequest(err error) HTTPError {
	return HTTPError{Code: http.StatusBadRequest, Err: err}
}

func internal(err error) HTTPError {
	return HTTPError{Code: http.StatusInternalServerError, Err: err}
}

func (gi *GiteaInterceptor) executeInterceptor(r *http.Request) ([]byte, error) {
	// Create a context
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var body bytes.Buffer
	defer r.Body.Close()
	if _, err := io.Copy(&body, r.Body); err != nil {
		return nil, internal(fmt.Errorf("failed to read body: %w", err))
	}
	var ireq triggersv1.InterceptorRequest
	if err := json.Unmarshal(body.Bytes(), &ireq); err != nil {
		return nil, badRequest(fmt.Errorf("failed to parse body as InterceptorRequest: %w", err))
	}
	gi.Logger.Debugf("Interceptor Request is: %+v", ireq)
	iresp := gi.Process(ctx, &ireq)
	gi.Logger.Infof("Interceptor response is: %+v", iresp)
	respBytes, err := json.Marshal(iresp)
	if err != nil {
		return nil, internal(err)
	}
	return respBytes, nil
}

// ErrInvalidContentType is returned when the content-type is not a JSON body.
var ErrInvalidContentType = errors.New("form parameter encoding not supported, please change the hook to send JSON payloads")

type GiteaInterceptor struct {
	SecretLister corev1lister.SecretLister
	Logger       *zap.SugaredLogger
}

func NewGiteaInterceptor(s corev1lister.SecretLister, l *zap.SugaredLogger) *GiteaInterceptor {
	return &GiteaInterceptor{
		SecretLister: s,
		Logger:       l,
	}
}

func (w *GiteaInterceptor) Process(ctx context.Context, r *triggersv1.InterceptorRequest) *triggersv1.InterceptorResponse {
	headers := interceptors.Canonical(r.Header)
	if v := headers.Get("Content-Type"); v == "application/x-www-form-urlencoded" {
		return interceptors.Fail(codes.InvalidArgument, ErrInvalidContentType.Error())
	}

	p := triggersv1.GitHubInterceptor{}
	if err := interceptors.UnmarshalParams(r.InterceptorParams, &p); err != nil {
		return interceptors.Failf(codes.InvalidArgument, "failed to parse interceptor params: %v", err)
	}

	// Check if the event type is in the allow-list
	if p.EventTypes != nil {
		actualEvent := headers.Get("X-Gitea-Event")
		isAllowed := false
		for _, allowedEvent := range p.EventTypes {
			if actualEvent == allowedEvent {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return interceptors.Failf(codes.FailedPrecondition, "event type %s is not allowed", actualEvent)
		}
	}

	// Next validate secrets
	if p.SecretRef != nil {
		// Check the secret to see if it is empty
		if p.SecretRef.SecretKey == "" {
			return interceptors.Fail(codes.FailedPrecondition, "gitea interceptor secretRef.secretKey is empty")
		}
		header := headers.Get("X-Gitea-Signature")
		if header == "" {
			return interceptors.Fail(codes.FailedPrecondition, "no X-Gitea-Signature header set")
		}

		ns, _ := triggersv1.ParseTriggerID(r.Context.TriggerID)
		secret, err := w.SecretLister.Secrets(ns).Get(p.SecretRef.SecretName)
		if err != nil {
			return interceptors.Failf(codes.FailedPrecondition, "error getting secret: %v", err)
		}
		secretToken := secret.Data[p.SecretRef.SecretKey]

		if err := validateSignature(header, []byte(r.Body), secretToken); err != nil {
			return interceptors.Fail(codes.FailedPrecondition, err.Error())
		}
	}

	return &triggersv1.InterceptorResponse{
		Continue: true,
	}
}

// genMAC generates the HMAC signature for a message provided the secret key
// and hashFunc.
func genMAC(message, key []byte, hashFunc func() hash.Hash) []byte {
	mac := hmac.New(hashFunc, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// checkMAC reports whether messageMAC is a valid HMAC tag for message.
func checkMAC(message, messageMAC, key []byte, hashFunc func() hash.Hash) bool {
	expectedMAC := genMAC(message, key, hashFunc)
	return hmac.Equal(messageMAC, expectedMAC)
}

// messageMAC returns the hex-decoded HMAC tag from the signature and its
// corresponding hash function.
func messageMAC(signature string) ([]byte, func() hash.Hash, error) {
	if signature == "" {
		return nil, nil, errors.New("missing signature")
	}

	var hashFunc func() hash.Hash

	hashFunc = sha256.New

	buf, err := hex.DecodeString(signature)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding signature %q: %v", signature, err)
	}
	return buf, hashFunc, nil
}

// validateSignature validates the signature for the given payload.
// signature is the gitea hash signature delivered in the X-Gitea-Signature header.
// payload is the JSON payload sent by gitea Webhooks.
// secretToken is the gitea Webhook secret token.
//
func validateSignature(signature string, payload, secretToken []byte) error {
	messageMAC, hashFunc, err := messageMAC(signature)
	if err != nil {
		return err
	}
	if !checkMAC(payload, messageMAC, secretToken, hashFunc) {
		return errors.New("payload signature check failed")
	}
	return nil
}