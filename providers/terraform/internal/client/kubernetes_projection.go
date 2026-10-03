package client

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
)

var projectionID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// KubernetesProjectionRaw never addresses another realm or lifecycle endpoint.
func (c *Client) KubernetesProjectionRaw(ctx context.Context, entitlement string) (json.RawMessage, error) {
	if !projectionID.MatchString(entitlement) {
		return nil, errors.New("one canonical entitlement UUID required")
	}
	var raw json.RawMessage
	err := c.request(ctx, "GET", c.cfg.Issuer+"/admin/api/v1/kubernetes/temporary-access/"+entitlement, "", nil, &raw)
	return raw, err
}
