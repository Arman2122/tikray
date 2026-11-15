package apiclient

import (
	"context"
	"errors"
	"net/http"
)

// Check the component before constructing a path even when an independent
// caller bypasses the CLI. A user-supplied selector never enters an error.
func imagePath(component string) (string, error) {
	if component != "tikray" && component != "runner" {
		return "", errors.New("apiclient: invalid image component")
	}
	return "/v1/images/" + component, nil
}
func (c *Client) ImageStatus(ctx context.Context, component string) (Response, error) {
	p, e := imagePath(component)
	if e != nil {
		return Response{}, e
	}
	return c.get(ctx, p)
}
func (c *Client) ImageUpdate(ctx context.Context, component, version string) (Response, error) {
	p, e := imagePath(component)
	if e != nil {
		return Response{}, e
	}
	return c.send(ctx, http.MethodPost, p+"/update", struct {
		Version string `json:"version"`
	}{version})
}
func (c *Client) ImageRollback(ctx context.Context, component string) (Response, error) {
	p, e := imagePath(component)
	if e != nil {
		return Response{}, e
	}
	return c.send(ctx, http.MethodPost, p+"/rollback", nil)
}
