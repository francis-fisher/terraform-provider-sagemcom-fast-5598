package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestComputeAuthKey(t *testing.T) {
	// Inputs from 01-login.har, regenerated with dummy password
	// This therefore doesn't test that the system generates identical
	// output to the router web interface, but tests that the client
	// generates the output we expect based on how we think the router
	// works. Hopefully this is a moot point!
	username := "admin"
	password := "some_secure_password"
	nonce := "88810e86271207f591c8f82aa3f58622"
	salt := "Q9Sn4I/gmeDMa9Z"
	cnonce := "6783452008529600000"
	expectedAuthKey := "fe358d2ed9e542365f007fcd535b6e38aa7df83078d3a6daf00258c5f7202b89faad76db956e288bef3ca2175a71a34d1203a7130deaa488129ee4dabbfb94d4"

	c, err := NewClient("http://127.0.0.1", username, password)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	authKey, err := c.computeAuthKey(nonce, salt, cnonce)
	if err != nil {
		t.Fatalf("computeAuthKey returned error: %v", err)
	}

	if authKey != expectedAuthKey {
		t.Errorf("authKey mismatch:\nexpected: %s\ngot:      %s", expectedAuthKey, authKey)
	}
}

func TestClientLoginFlow(t *testing.T) {
	// Set up a mock HTTP server simulating the router endpoints
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/open":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			metadata := []OpenResponse{
				{
					InternalFirmwareVersion: "sw2024.07.205_Prod",
					ExternalFirmwareVersion: "SGQB320000205",
					SerialNumber:            "N726061A2000613",
					GatewayIP:               "192.168.1.1",
				},
			}
			_ = json.NewEncoder(w).Encode(metadata)

		case "/api/v2/home":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			homeData := []HomeResponse{
				{
					ProductClass: "FAST5598",
				},
			}
			_ = json.NewEncoder(w).Encode(homeData)

		case "/api/v1/login-params":
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			_ = r.ParseForm()
			if r.Form.Get("login") != "admin" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "salt", Value: "Q9Sn4I/gmeDMa9Z", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "nonce", Value: "88810e86271207f591c8f82aa3f58622", Path: "/"})
			w.WriteHeader(http.StatusNoContent)

		case "/api/v1/login":
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			_ = r.ParseForm()
			if r.Form.Get("login") != "admin" ||
				r.Form.Get("auth_key") == "" ||
				r.Form.Get("cnonce") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	c, err := NewClient(server.URL, "admin", "some_secure_password")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	err = c.Login(ctx)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Verify metadata was loaded successfully
	if c.InternalFirmwareVersion != "sw2024.07.205_Prod" {
		t.Errorf("expected InternalFirmwareVersion 'sw2024.07.205_Prod', got '%s'", c.InternalFirmwareVersion)
	}
	if c.SerialNumber != "N726061A2000613" {
		t.Errorf("expected SerialNumber 'N726061A2000613', got '%s'", c.SerialNumber)
	}

	// Verify ProductClass is empty after login
	if c.ProductClass != "" {
		t.Errorf("expected ProductClass to be empty after login, got '%s'", c.ProductClass)
	}

	// Explicitly fetch home metadata on-demand and verify ProductClass is populated
	err = c.fetchHomeMetadata(ctx)
	if err != nil {
		t.Fatalf("fetchHomeMetadata failed: %v", err)
	}
	if c.ProductClass != "FAST5598" {
		t.Errorf("expected ProductClass 'FAST5598' after fetchHomeMetadata, got '%s'", c.ProductClass)
	}
}
