// Package operator reconciles bounded, tenant-pinned Kubernetes identity objects.
package operator

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Metadata struct {
	Name              string     `json:"name"`
	Namespace         string     `json:"namespace"`
	UID               string     `json:"uid"`
	ResourceVersion   string     `json:"resourceVersion"`
	Generation        int64      `json:"generation"`
	Finalizers        []string   `json:"finalizers,omitempty"`
	DeletionTimestamp *time.Time `json:"deletionTimestamp,omitempty"`
}
type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
	ObservedGeneration int64     `json:"observedGeneration"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}
type Status struct {
	ObservedGeneration         int64       `json:"observedGeneration"`
	RemoteID                   string      `json:"remoteId,omitempty"`
	RemoteRevision             string      `json:"remoteRevision,omitempty"`
	ObservedDeletionProtection *bool       `json:"observedDeletionProtection,omitempty"`
	Conditions                 []Condition `json:"conditions"`
}
type Object struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   Metadata        `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
	Status     Status          `json:"status,omitempty"`
}
type Ref struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}
type BindingSpec struct {
	TenantID       string `json:"tenantId"`
	Issuer         string `json:"issuer"`
	ClientID       string `json:"clientId"`
	ClusterID      string `json:"clusterId"`
	Authentication Ref    `json:"authenticationKeySecretRef"`
	DPoP           Ref    `json:"dpopKeySecretRef"`
	CA             *Ref   `json:"issuerCaSecretRef,omitempty"`
}
type KubeError struct{ Status int }

func (e *KubeError) Error() string {
	return fmt.Sprintf("Kubernetes operation refused (HTTP %d)", e.Status)
}

type Kube struct {
	base      string
	tokenFile string
	http      *http.Client
	namespace string
}

func NewKube(base, tokenFile, caFile, namespace string) (*Kube, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid Kubernetes HTTPS origin")
	}
	raw, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("Kubernetes CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, errors.New("invalid Kubernetes CA")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &Kube{base: strings.TrimRight(base, "/"), tokenFile: tokenFile, namespace: namespace, http: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("Kubernetes redirects refused") }}}, nil
}
func (k *Kube) request(ctx context.Context, method, path string, body any, out any) error {
	token, err := os.ReadFile(k.tokenFile)
	if err != nil || len(token) > 16384 || len(bytes.TrimSpace(token)) == 0 {
		return errors.New("projected Kubernetes credential unavailable")
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil || len(raw) > 131072 {
			return errors.New("oversized Kubernetes write")
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, reader)
	if err != nil {
		return errors.New("invalid Kubernetes request")
	}
	req.Header.Set("Authorization", "Bearer "+string(bytes.TrimSpace(token)))
	req.Header.Set("Content-Type", "application/json")
	if method == "PATCH" {
		req.Header.Set("Content-Type", "application/merge-patch+json")
	}
	res, err := k.http.Do(req)
	if err != nil {
		return errors.New("Kubernetes unavailable")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2097153))
	if err != nil || len(raw) > 2097152 {
		return errors.New("oversized Kubernetes response")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &KubeError{res.StatusCode}
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return errors.New("invalid Kubernetes response")
	}
	return nil
}
func (k *Kube) identityPath(plural string) string {
	return "/apis/identity.asterius.io/v1alpha1/namespaces/" + url.PathEscape(k.namespace) + "/" + plural
}
func (k *Kube) Get(ctx context.Context, plural, name string) (Object, error) {
	var out Object
	err := k.request(ctx, "GET", k.identityPath(plural)+"/"+url.PathEscape(name), nil, &out)
	return out, err
}
func (k *Kube) List(ctx context.Context, plural string) ([]Object, error) {
	var out []Object
	continuation := ""
	for page := 0; page < 20; page++ {
		var list struct {
			Items    []Object `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		err := k.request(ctx, "GET", k.identityPath(plural)+"?limit=20&continue="+url.QueryEscape(continuation), nil, &list)
		if err != nil {
			return nil, err
		}
		out = append(out, list.Items...)
		continuation = list.Metadata.Continue
		if continuation == "" {
			return out, nil
		}
	}
	return nil, errors.New("namespace inventory exceeds supported bound")
}
func (k *Kube) Update(ctx context.Context, plural string, o Object, statusOnly bool) error {
	path := k.identityPath(plural) + "/" + url.PathEscape(o.Metadata.Name)
	metadata := map[string]any{"resourceVersion": o.Metadata.ResourceVersion}
	patch := map[string]any{"metadata": metadata}
	if statusOnly {
		path += "/status"
		patch["status"] = o.Status
	} else {
		metadata["finalizers"] = o.Metadata.Finalizers
	}
	return k.request(ctx, "PATCH", path, patch, nil)
}
func (k *Kube) Secret(ctx context.Context, ref Ref) ([]byte, error) {
	var secret struct {
		Data map[string][]byte `json:"data"`
	}
	err := k.request(ctx, "GET", "/api/v1/namespaces/"+url.PathEscape(k.namespace)+"/secrets/"+url.PathEscape(ref.Name), nil, &secret)
	if err != nil {
		return nil, err
	}
	raw, found := secret.Data[ref.Key]
	if !found || len(raw) == 0 || len(raw) > 65536 {
		return nil, errors.New("referenced Secret key unavailable")
	}
	return raw, nil
}

type Lease struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       struct {
		HolderIdentity       *string    `json:"holderIdentity,omitempty"`
		LeaseDurationSeconds int64      `json:"leaseDurationSeconds"`
		RenewTime            *time.Time `json:"renewTime,omitempty"`
	} `json:"spec"`
}

func (k *Kube) Acquire(ctx context.Context, holder string, now time.Time) (bool, error) {
	path := "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(k.namespace) + "/leases/asterius-controller"
	var lease Lease
	if err := k.request(ctx, "GET", path, nil, &lease); err != nil {
		return false, err
	}
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != holder && lease.Spec.RenewTime != nil && now.Before(lease.Spec.RenewTime.Add(time.Duration(lease.Spec.LeaseDurationSeconds)*time.Second)) {
		return false, nil
	}
	lease.Spec.HolderIdentity = &holder
	lease.Spec.RenewTime = &now
	lease.Spec.LeaseDurationSeconds = 30
	// coordination.k8s.io Lease uses metav1.MicroTime, whose wire decoder
	// requires exactly six fractional digits rather than Go's RFC3339Nano.
	spec := map[string]any{"holderIdentity": holder, "leaseDurationSeconds": 30, "renewTime": now.UTC().Format("2006-01-02T15:04:05.000000Z07:00")}
	err := k.request(ctx, "PATCH", path, map[string]any{"metadata": map[string]any{"resourceVersion": lease.Metadata.ResourceVersion}, "spec": spec}, nil)
	return err == nil, err
}
