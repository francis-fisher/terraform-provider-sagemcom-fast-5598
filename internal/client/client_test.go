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

func TestDHCPClientOperations(t *testing.T) {
	// Keep track of our virtual clients list
	clients := []DHCPClient{
		{
			ID:         1,
			Hostname:   "shaw",
			IPAddress:  "192.168.1.6",
			MACAddress: "02:00:00:00:00:01",
			Enabled:    true,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if r.URL.Path == "/api/v1/dhcp/clients" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				wrapper := []DHCPClientsWrapper{}
				w1 := DHCPClientsWrapper{}
				w1.DHCP.Clients = clients
				wrapper = append(wrapper, w1)
				_ = json.NewEncoder(w).Encode(wrapper)
				return
			}
		case "POST":
			if r.URL.Path == "/api/v1/dhcp/clients" {
				_ = r.ParseForm()
				enabled := r.Form.Get("enable") == "1"
				hostname := r.Form.Get("hostname")
				mac := r.Form.Get("macaddress")
				ip := r.Form.Get("ipaddress")

				newClient := DHCPClient{
					ID:         2,
					Hostname:   hostname,
					IPAddress:  ip,
					MACAddress: mac,
					Enabled:    enabled,
				}
				clients = append(clients, newClient)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		case "PUT":
			if r.URL.Path == "/api/v1/dhcp/clients/2" {
				_ = r.ParseForm()
				for idx, val := range clients {
					if val.ID == 2 {
						if r.Form.Get("enable") != "" {
							clients[idx].Enabled = r.Form.Get("enable") == "1"
						}
						if r.Form.Get("hostname") != "" {
							clients[idx].Hostname = r.Form.Get("hostname")
						}
						if r.Form.Get("macaddress") != "" {
							clients[idx].MACAddress = r.Form.Get("macaddress")
						}
						if r.Form.Get("ipaddress") != "" {
							clients[idx].IPAddress = r.Form.Get("ipaddress")
						}
					}
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		case "DELETE":
			if r.URL.Path == "/api/v1/dhcp/clients/2" {
				// Remove the second client from list
				var updated []DHCPClient
				for _, c := range clients {
					if c.ID != 2 {
						updated = append(updated, c)
					}
				}
				clients = updated
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c, err := NewClient(server.URL, "admin", "some_secure_password")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// 1. Test GET clients
	list, err := c.GetDHCPReservedAddresses(ctx)
	if err != nil {
		t.Fatalf("GetDHCPReservedAddresses failed: %v", err)
	}
	if len(list) != 1 || list[0].Hostname != "shaw" {
		t.Errorf("Unexpected clients list: %+v", list)
	}

	// 2. Test POST client
	newC, err := c.AddDHCPReservedAddress(ctx, "calloway", "02:00:00:00:00:04", "192.168.1.5", true)
	if err != nil {
		t.Fatalf("AddDHCPReservedAddress failed: %v", err)
	}
	if newC.ID != 2 || newC.Hostname != "calloway" {
		t.Errorf("Unexpected created client: %+v", newC)
	}

	// Verify it was added to the list
	list, err = c.GetDHCPReservedAddresses(ctx)
	if err != nil {
		t.Fatalf("GetDHCPReservedAddresses failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("Expected 2 clients after addition, got %d", len(list))
	}

	// Test PUT update
	hostnameVal := "new-calloway"
	macVal := "02:00:00:00:00:04"
	ipVal := "192.168.1.19"
	enabledVal := true
	err = c.UpdateDHCPReservedAddress(ctx, 2, &hostnameVal, &macVal, &ipVal, &enabledVal)
	if err != nil {
		t.Fatalf("UpdateDHCPReservedAddress failed: %v", err)
	}

	// Verify update was applied
	list, err = c.GetDHCPReservedAddresses(ctx)
	if err != nil {
		t.Fatalf("GetDHCPReservedAddresses failed: %v", err)
	}
	for _, cl := range list {
		if cl.ID == 2 {
			if cl.Hostname != "new-calloway" || cl.IPAddress != "192.168.1.19" {
				t.Errorf("Unexpected updated client fields: %+v", cl)
			}
		}
	}

	// 3. Test DELETE client
	err = c.DeleteDHCPReservedAddress(ctx, 2)
	if err != nil {
		t.Fatalf("DeleteDHCPReservedAddress failed: %v", err)
	}

	// Verify it was removed from the list
	list, err = c.GetDHCPReservedAddresses(ctx)
	if err != nil {
		t.Fatalf("GetDHCPReservedAddresses failed: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("Expected 1 client after deletion, got %d", len(list))
	}
}
