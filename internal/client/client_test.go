package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestNATOperations(t *testing.T) {
	rules := []PortForward{
		{
			ID:              59,
			Enabled:         true,
			Description:     "bastion 2222",
			ExternalIP:      "",
			ExternalPort:    2222,
			ExternalEndPort: 0,
			InternalPort:    2222,
			InternalIP:      "198.51.100.1",
			Service:         "OTHER",
			Protocol:        "tcp",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if r.URL.Path == "/api/v1/nat/rules" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				wrapper := []NATRulesWrapper{}
				w1 := NATRulesWrapper{}
				w1.NAT.Enabled = true
				w1.NAT.Rules = rules
				wrapper = append(wrapper, w1)
				_ = json.NewEncoder(w).Encode(wrapper)
				return
			}
		case "POST":
			if r.URL.Path == "/api/v1/nat/rules" {
				_ = r.ParseForm()
				enabled := r.Form.Get("enable") == "1"
				description := r.Form.Get("description")
				protocol := r.Form.Get("protocol")
				ip := r.Form.Get("ipaddress")
				extPort, _ := strconv.Atoi(r.Form.Get("externalPort"))
				intPort, _ := strconv.Atoi(r.Form.Get("internalPort"))
				extEndPort, _ := strconv.Atoi(r.Form.Get("externalEndPort"))

				newRule := PortForward{
					ID:              60,
					Enabled:         enabled,
					Description:     description,
					ExternalIP:      "",
					ExternalPort:    extPort,
					ExternalEndPort: extEndPort,
					InternalPort:    intPort,
					InternalIP:      ip,
					Service:         "OTHER",
					Protocol:        protocol,
				}
				rules = append(rules, newRule)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		case "PUT":
			if r.URL.Path == "/api/v1/nat/rules/60" {
				_ = r.ParseForm()
				for idx, val := range rules {
					if val.ID == 60 {
						if r.Form.Get("enable") != "" {
							rules[idx].Enabled = r.Form.Get("enable") == "1"
						}
						if r.Form.Get("description") != "" {
							rules[idx].Description = r.Form.Get("description")
						}
						if r.Form.Get("protocol") != "" {
							rules[idx].Protocol = r.Form.Get("protocol")
						}
						if r.Form.Get("ipaddress") != "" {
							rules[idx].InternalIP = r.Form.Get("ipaddress")
						}
						if r.Form.Get("externalPort") != "" {
							rules[idx].ExternalPort, _ = strconv.Atoi(r.Form.Get("externalPort"))
						}
						if r.Form.Get("internalPort") != "" {
							rules[idx].InternalPort, _ = strconv.Atoi(r.Form.Get("internalPort"))
						}
						if r.Form.Get("externalEndPort") != "" {
							rules[idx].ExternalEndPort, _ = strconv.Atoi(r.Form.Get("externalEndPort"))
						}
					}
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		case "DELETE":
			if r.URL.Path == "/api/v1/nat/rules/60" {
				var updated []PortForward
				for _, rl := range rules {
					if rl.ID != 60 {
						updated = append(updated, rl)
					}
				}
				rules = updated
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

	// 1. Get Port Forwards
	list, err := c.GetPortForwards(ctx)
	if err != nil {
		t.Fatalf("GetPortForwards failed: %v", err)
	}
	if len(list) != 1 || list[0].Description != "bastion 2222" {
		t.Errorf("Unexpected rules list: %+v", list)
	}

	// 2. Add Port Forward
	newRl, err := c.AddPortForward(ctx, "ssh-server", "198.51.100.2", "", 2223, 2222, 0, "tcp", true)
	if err != nil {
		t.Fatalf("AddPortForward failed: %v", err)
	}
	if newRl.ID != 60 || newRl.Description != "ssh-server" {
		t.Errorf("Unexpected created rule: %+v", newRl)
	}

	// Verify it was added
	list, err = c.GetPortForwards(ctx)
	if err != nil {
		t.Fatalf("GetPortForwards failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(list))
	}

	// Update Port Forward
	err = c.UpdatePortForward(ctx, 60, "updated-ssh", "198.51.100.3", "", 2224, 22, 0, "udp", false)
	if err != nil {
		t.Fatalf("UpdatePortForward failed: %v", err)
	}

	// Verify update was applied
	list, err = c.GetPortForwards(ctx)
	if err != nil {
		t.Fatalf("GetPortForwards failed: %v", err)
	}
	for _, rl := range list {
		if rl.ID == 60 {
			if rl.Description != "updated-ssh" || rl.InternalIP != "198.51.100.3" || rl.ExternalPort != 2224 || rl.Enabled != false {
				t.Errorf("Unexpected updated rule fields: %+v", rl)
			}
		}
	}

	// 3. Delete Port Forward
	err = c.DeletePortForward(ctx, 60)
	if err != nil {
		t.Fatalf("DeletePortForward failed: %v", err)
	}

	// Verify it was removed
	list, err = c.GetPortForwards(ctx)
	if err != nil {
		t.Fatalf("GetPortForwards failed: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("Expected 1 rule after deletion, got %d", len(list))
	}
}

func TestDHCPServerAndDNSOperations(t *testing.T) {
	dhcpSettings := DHCPServer{
		Enable:     true,
		MinAddress: "192.168.1.5",
		MaxAddress: "192.168.1.250",
		LeaseTime:  43200,
		IPRouter:   "192.168.1.1",
		SubnetMask: "255.255.255.0",
	}

	dnsIPv4Settings := DNSData{
		Interface: "LAN",
		DNSMode:   "STATIC",
		Static: DNSStatic{
			ProviderList: "Custom",
			Provider:     "Custom",
			Servers:      "198.51.100.1,198.51.100.2",
		},
		Dynamic: []DNSDynamic{
			{Server: "198.51.100.1,198.51.100.2"},
		},
	}

	dnsIPv6Settings := DNSData{
		Interface: "",
		DNSMode:   "STATIC",
		Static: DNSStatic{
			ProviderList: "",
			Provider:     "Custom",
			Servers:      "2001:db8:1::2::16:5,2001:db8:1::2::16:6",
		},
		Dynamic: []DNSDynamic{
			{Server: "fe80::0200:00ff:fe00:0003"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if r.URL.Path == "/api/v1/dhcp" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				wrapper := []DHCPServerWrapper{
					{
						Hostname: "mygateway",
						DHCP:     dhcpSettings,
					},
				}
				_ = json.NewEncoder(w).Encode(wrapper)
				return
			}
			if r.URL.Path == "/api/v1/dns/ipv4" {
				if r.URL.Query().Get("interface") != "LAN" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				wrapper := []DNSWrapper{
					{
						DNS: dnsIPv4Settings,
					},
				}
				_ = json.NewEncoder(w).Encode(wrapper)
				return
			}
			if r.URL.Path == "/api/v1/dns/ipv6" {
				if r.URL.Query().Get("interface") != "LAN" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				wrapper := []DNSWrapper{
					{
						DNS: dnsIPv6Settings,
					},
				}
				_ = json.NewEncoder(w).Encode(wrapper)
				return
			}
		case "PUT":
			if r.URL.Path == "/api/v1/dhcp" {
				_ = r.ParseForm()
				dhcpSettings.Enable = r.Form.Get("enable") == "1"
				dhcpSettings.MinAddress = r.Form.Get("minaddress")
				dhcpSettings.MaxAddress = r.Form.Get("maxaddress")
				leaseVal, _ := strconv.Atoi(r.Form.Get("leasetime"))
				dhcpSettings.LeaseTime = leaseVal
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if r.URL.Path == "/api/v1/dns/ipv4" {
				_ = r.ParseForm()
				if r.Form.Get("interface") != "LAN" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				enableStatic := r.Form.Get("enableStatic") == "1"
				if enableStatic {
					dnsIPv4Settings.DNSMode = "STATIC"
				} else {
					dnsIPv4Settings.DNSMode = "DYNAMIC"
				}
				dnsIPv4Settings.Static.Servers = r.Form.Get("servers")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if r.URL.Path == "/api/v1/dns/ipv6" {
				_ = r.ParseForm()
				if r.Form.Get("interface") != "LAN" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				enableStatic := r.Form.Get("enableStatic") == "1"
				if enableStatic {
					dnsIPv6Settings.DNSMode = "STATIC"
				} else {
					dnsIPv6Settings.DNSMode = "DYNAMIC"
				}
				dnsIPv6Settings.Static.Servers = r.Form.Get("servers")
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

	// Test DHCP server GET & PUT
	dhcp, err := c.GetDHCPServer(ctx)
	if err != nil {
		t.Fatalf("GetDHCPServer failed: %v", err)
	}
	if !dhcp.Enable || dhcp.MinAddress != "192.168.1.5" || dhcp.MaxAddress != "192.168.1.250" || dhcp.LeaseTime != 43200 {
		t.Errorf("Unexpected DHCP server settings: %+v", dhcp)
	}

	err = c.UpdateDHCPServer(ctx, false, "192.168.1.10", "192.168.1.200", 86400)
	if err != nil {
		t.Fatalf("UpdateDHCPServer failed: %v", err)
	}

	dhcp, err = c.GetDHCPServer(ctx)
	if err != nil {
		t.Fatalf("GetDHCPServer failed: %v", err)
	}
	if dhcp.Enable || dhcp.MinAddress != "192.168.1.10" || dhcp.MaxAddress != "192.168.1.200" || dhcp.LeaseTime != 86400 {
		t.Errorf("Unexpected updated DHCP server settings: %+v", dhcp)
	}

	// Test DNS IPv4 GET & PUT
	dns4, err := c.GetDNSIPv4(ctx)
	if err != nil {
		t.Fatalf("GetDNSIPv4 failed: %v", err)
	}
	if dns4.DNSMode != "STATIC" || dns4.Static.Servers != "198.51.100.1,198.51.100.2" {
		t.Errorf("Unexpected DNS IPv4 settings: %+v", dns4)
	}

	err = c.UpdateDNSIPv4(ctx, false, "")
	if err != nil {
		t.Fatalf("UpdateDNSIPv4 failed: %v", err)
	}

	dns4, err = c.GetDNSIPv4(ctx)
	if err != nil {
		t.Fatalf("GetDNSIPv4 failed: %v", err)
	}
	if dns4.DNSMode != "DYNAMIC" || dns4.Static.Servers != "" {
		t.Errorf("Unexpected updated DNS IPv4 settings: %+v", dns4)
	}

	// Test DNS IPv6 GET & PUT
	dns6, err := c.GetDNSIPv6(ctx)
	if err != nil {
		t.Fatalf("GetDNSIPv6 failed: %v", err)
	}
	if dns6.DNSMode != "STATIC" || dns6.Static.Servers != "2001:db8:1::2::16:5,2001:db8:1::2::16:6" {
		t.Errorf("Unexpected DNS IPv6 settings: %+v", dns6)
	}

	err = c.UpdateDNSIPv6(ctx, true, "2001:db8:1::4::16:5,2001:db8:1::4::16:6")
	if err != nil {
		t.Fatalf("UpdateDNSIPv6 failed: %v", err)
	}

	dns6, err = c.GetDNSIPv6(ctx)
	if err != nil {
		t.Fatalf("GetDNSIPv6 failed: %v", err)
	}
	if dns6.DNSMode != "STATIC" || dns6.Static.Servers != "2001:db8:1::4::16:5,2001:db8:1::4::16:6" {
		t.Errorf("Unexpected updated DNS IPv6 settings: %+v", dns6)
	}
}
