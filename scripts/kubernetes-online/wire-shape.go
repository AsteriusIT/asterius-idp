// Controlled standard-library reproduction, not a live Kubernetes test.
// Field shapes/tags correspond to Kubernetes v1.35 TokenReview and ObjectMeta.
// Upstream Serializer.doEncode delegates to encoding/json.NewEncoder.
package main

import (
	"encoding/json"
	"fmt"
)

type userInfo struct {
	Username string              `json:"username,omitempty"`
	UID      string              `json:"uid,omitempty"`
	Groups   []string            `json:"groups,omitempty"`
	Extra    map[string][]string `json:"extra,omitempty"`
}
type status struct {
	Authenticated bool     `json:"authenticated,omitempty"`
	User          userInfo `json:"user,omitempty"`
	Audiences     []string `json:"audiences,omitempty"`
	Error         string   `json:"error,omitempty"`
}
type spec struct {
	Token     string   `json:"token,omitempty"`
	Audiences []string `json:"audiences,omitempty"`
}
type metadata struct {
	// metav1.Time.MarshalJSON emits null for zero creationTimestamp.
	CreationTimestamp *string `json:"creationTimestamp"`
}
type review struct {
	APIVersion string   `json:"apiVersion,omitempty"`
	Kind       string   `json:"kind,omitempty"`
	Metadata   metadata `json:"metadata,omitempty"`
	Spec       spec     `json:"spec"`
	Status     status   `json:"status,omitempty"`
}

func main() {
	value := review{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview",
		Spec: spec{Token: "controlled-not-a-credential", Audiences: []string{"controlled-cluster"}}}
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("controlled JSON marshal failed")
	}
	var shape map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &shape); err != nil {
		panic("controlled JSON shape failed")
	}
	// Never print the token or request spec. Only prove zero-value wire fields.
	fmt.Printf("{\"metadata\":%s,\"status\":%s}\n", shape["metadata"], shape["status"])
}
