package processor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"golang.org/x/oauth2"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestBindOAuthTokenToRequest(t *testing.T) {
	t.Run("context without token source", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		if err != nil {
			t.Fatalf("create request failed: %v", err)
		}

		err = bindOAuthTokenToRequest(req, context.TODO())
		if err != nil {
			t.Fatalf("bind token failed: %v", err)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
	})

	t.Run("context with token source", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com", nil)
		if err != nil {
			t.Fatalf("create request failed: %v", err)
		}

		tok := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "abc123", TokenType: "Bearer"})
		tokenCtx := context.WithValue(context.Background(), openapi.ContextOAuth2, tok)

		err = bindOAuthTokenToRequest(req, tokenCtx)
		if err != nil {
			t.Fatalf("bind token failed: %v", err)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer abc123" {
			t.Fatalf("authorization header = %q, want %q", got, "Bearer abc123")
		}
	})
}

func TestPostSmfEventExposureNotificationToAfWithToken(t *testing.T) {
	originalClient := afCallbackHTTPClient
	t.Cleanup(func() { afCallbackHTTPClient = originalClient })

	afCallbackHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Authorization"); got != "Bearer token-for-af" {
			t.Fatalf("authorization header = %q, want %q", got, "Bearer token-for-af")
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}

	tok := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token-for-af", TokenType: "Bearer"})
	tokenCtx := context.WithValue(context.Background(), openapi.ContextOAuth2, tok)

	eeNotif := &models.NsmfEventExposureNotification{NotifId: "notif-1"}
	if err := postSmfEventExposureNotificationToAf("http://af.example.com/notify", eeNotif, tokenCtx); err != nil {
		t.Fatalf("post callback failed: %v", err)
	}
}

func TestPostSmfEventExposureNotificationToAfNon2xx(t *testing.T) {
	originalClient := afCallbackHTTPClient
	t.Cleanup(func() { afCallbackHTTPClient = originalClient })

	afCallbackHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(strings.NewReader("forbidden")),
			Header:     make(http.Header),
		}, nil
	})}

	eeNotif := &models.NsmfEventExposureNotification{NotifId: "notif-2"}
	err := postSmfEventExposureNotificationToAf("http://af.example.com/notify", eeNotif, context.TODO())
	if err == nil {
		t.Fatal("expected error when AF callback returns non-2xx")
	}
}
