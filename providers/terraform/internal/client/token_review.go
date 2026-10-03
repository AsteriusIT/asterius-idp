package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
)

// TokenReview addresses only the configured issuing tenant and human client.
// Neither the bearer ID assertion nor its claims can select a target issuer.
func (c *Client) TokenReview(ctx context.Context, humanClient string, raw json.RawMessage) (json.RawMessage, error) {
	if humanClient == "" || len(humanClient) > 2048 || len(raw) > 65536 || !json.Valid(raw) {
		return nil, errors.New("invalid bounded online review")
	}
	var response json.RawMessage
	err := c.request(ctx, "POST", c.cfg.Issuer+"/admin/api/v1/clients/"+url.PathEscape(humanClient)+"/kubernetes/reviews", "", raw, &response)
	return response, err
}
