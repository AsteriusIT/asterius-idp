package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var tenantPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
var revisionPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ParseID(id string) ([]string, error) {
	if len(id) > 4096 {
		return nil, errors.New("invalid import identity")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(id)
	if err != nil {
		return nil, errors.New("invalid import identity")
	}
	var p []string
	if json.Unmarshal(raw, &p) != nil || len(p) < 3 || !tenantPattern.MatchString(p[0]) || !ValidKind(p[1]) {
		return nil, errors.New("invalid import identity")
	}
	size := 3
	if p[1] == "membership" {
		size = 4
	}
	if len(p) != size {
		return nil, errors.New("invalid import identity")
	}
	for _, key := range p[2:] {
		if key == "" || len(key) > 2048 {
			return nil, errors.New("invalid import identity")
		}
	}
	switch p[1] {
	case "tenant":
		if p[2] != p[0] {
			return nil, errors.New("invalid tenant import identity")
		}
	case "group", "membership":
		for _, key := range p[2:] {
			if !uuidPattern.MatchString(key) {
				return nil, errors.New("UUID identities must have canonical lowercase hyphenated spelling")
			}
		}
	case "policy":
		if p[2] != "policy" {
			return nil, errors.New("invalid policy import identity")
		}
	case "resource":
		u, err := url.Parse(p[2])
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, errors.New("invalid audience import identity")
		}
	}
	return p, nil
}
func PublicSpec(raw []byte) error {
	if len(raw) > 65536 {
		return errors.New("specification exceeds 64 KiB")
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	tokens.UseNumber()
	if err := uniqueValue(tokens, 0); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return errors.New("specification must be a JSON object")
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF {
		return errors.New("invalid specification")
	}
	if _, ok := value.(map[string]any); !ok {
		return errors.New("specification must be a JSON object")
	}
	return publicValue(value)
}
func publicValue(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for k, item := range v {
			switch strings.ToLower(k) {
			case "client_secret", "client_secret_hash", "password", "private_key", "private_key_pem", "access_token", "refresh_token", "registration_access_token", "registration_client_uri":
				return errors.New("credential material is forbidden in public specifications")
			}
			if _, jwk := v["kty"]; jwk {
				switch k {
				case "d", "p", "q", "dp", "dq", "qi", "oth", "k":
					return errors.New("private or symmetric JWK material is forbidden")
				}
			}
			if err := publicValue(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := publicValue(item); err != nil {
				return err
			}
		}
	case string:
		if strings.Contains(v, "-----BEGIN") && strings.Contains(v, "PRIVATE KEY-----") {
			return errors.New("private PEM material is forbidden")
		}
	}
	return nil
}
func Canonical(raw []byte) (string, error) {
	if err := PublicSpec(raw); err != nil {
		return "", err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", errors.New("invalid specification")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", errors.New("invalid specification")
	}
	return string(encoded), nil
}
func ValidateDocument(d Document, id, kind string) error {
	parts, err := ParseID(d.ID)
	if err != nil || d.ContractVersion != 1 || d.ID != id || d.Kind != kind || parts[1] != kind || !revisionPattern.MatchString(d.Revision) {
		return errors.New("invalid management document")
	}
	if d.Owner != nil {
		var owner []string
		if json.Unmarshal([]byte(*d.Owner), &owner) != nil || len(owner) != 2 {
			return errors.New("invalid management owner")
		}
	}
	for _, origin := range d.Origin {
		if err := PublicSpec(origin); err != nil {
			return err
		}
	}
	return PublicSpec(d.Spec)
}

// Reject duplicate fields before Go's map decoder could hide rejected material or ambiguous intent.
func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("specification nesting is too deep")
	}
	token, err := d.Token()
	if err != nil {
		return errors.New("invalid specification")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return errors.New("invalid specification")
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate specification field")
			}
			seen[name] = true
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid specification")
	}
	if _, err := d.Token(); err != nil {
		return errors.New("invalid specification")
	}
	return nil
}
