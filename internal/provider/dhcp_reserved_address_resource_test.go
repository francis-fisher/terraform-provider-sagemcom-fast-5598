// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync"
	"testing"

	"github.com/francis-fisher/terraform-provider-sagemcom-fast-5598/internal/client"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

type mockRouterServer struct {
	mu      sync.Mutex
	clients map[int]client.DHCPClient
	nextID  int
}

func newMockRouterServer() *mockRouterServer {
	return &mockRouterServer{
		clients: make(map[int]client.DHCPClient),
		nextID:  1,
	}
}

func (m *mockRouterServer) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/open", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		metadata := []client.OpenResponse{
			{
				InternalFirmwareVersion: "sw2024.07.205_Prod",
				ExternalFirmwareVersion: "SGQB320000205",
				SerialNumber:            "N726061A2000613",
				GatewayIP:               "192.168.1.1",
			},
		}
		_ = json.NewEncoder(w).Encode(metadata)
	})

	mux.HandleFunc("/api/v2/home", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		homeData := []client.HomeResponse{
			{
				ProductClass: "FAST5598",
			},
		}
		_ = json.NewEncoder(w).Encode(homeData)
	})

	mux.HandleFunc("/api/v1/login-params", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
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
	})

	mux.HandleFunc("/api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
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
	})

	clientDetailRegex := regexp.MustCompile(`^/api/v1/dhcp/clients/(\d+)$`)

	mux.HandleFunc("/api/v1/dhcp/clients", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method == http.MethodGet {
			var clientList []client.DHCPClient
			for _, c := range m.clients {
				clientList = append(clientList, c)
			}
			w.Header().Set("Content-Type", "application/json")
			wrapper := []client.DHCPClientsWrapper{}
			w1 := client.DHCPClientsWrapper{}
			w1.DHCP.Clients = clientList
			wrapper = append(wrapper, w1)
			_ = json.NewEncoder(w).Encode(wrapper)
			return
		}

		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			enabled := r.Form.Get("enable") == "1"
			hostname := r.Form.Get("hostname")
			mac := r.Form.Get("macaddress")
			ip := r.Form.Get("ipaddress")

			id := m.nextID
			m.nextID++

			newClient := client.DHCPClient{
				ID:         id,
				Hostname:   hostname,
				IPAddress:  ip,
				MACAddress: mac,
				Enabled:    enabled,
			}
			m.clients[id] = newClient
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// Handle the detailed client endpoints (PUT/DELETE)
	mux.HandleFunc("/api/v1/dhcp/clients/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		matches := clientDetailRegex.FindStringSubmatch(r.URL.Path)
		if len(matches) < 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		id, err := strconv.Atoi(matches[1])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.Method == http.MethodPut {
			_ = r.ParseForm()
			c, exists := m.clients[id]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Form.Get("enable") != "" {
				c.Enabled = r.Form.Get("enable") == "1"
			}
			if r.Form.Get("hostname") != "" {
				c.Hostname = r.Form.Get("hostname")
			}
			if r.Form.Get("macaddress") != "" {
				c.MACAddress = r.Form.Get("macaddress")
			}
			if r.Form.Get("ipaddress") != "" {
				c.IPAddress = r.Form.Get("ipaddress")
			}
			m.clients[id] = c
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method == http.MethodDelete {
			if _, exists := m.clients[id]; !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(m.clients, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	return mux
}

func TestAccDHCPReservedAddressResource(t *testing.T) {
	mockServer := newMockRouterServer()
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. Create and Read testing
			{
				Config: testAccDHCPReservedAddressConfig(server.URL, "00:11:22:33:44:55", "192.168.1.100", "test-host", true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("id"),
						knownvalue.StringExact("1"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("mac_address"),
						knownvalue.StringExact("00:11:22:33:44:55"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("ip_address"),
						knownvalue.StringExact("192.168.1.100"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("hostname"),
						knownvalue.StringExact("test-host"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("enabled"),
						knownvalue.Bool(true),
					),
				},
			},
			// 2. ImportState testing
			{
				ResourceName:      "sagemcom_dhcp_reserved_address.test",
				ImportState:       true,
				ImportStateId:     "00:11:22:33:44:55",
				ImportStateVerify: true,
			},
			// 3. Update and Read testing
			{
				Config: testAccDHCPReservedAddressConfig(server.URL, "00:11:22:33:44:55", "192.168.1.101", "updated-host", false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("id"),
						knownvalue.StringExact("1"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("mac_address"),
						knownvalue.StringExact("00:11:22:33:44:55"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("ip_address"),
						knownvalue.StringExact("192.168.1.101"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("hostname"),
						knownvalue.StringExact("updated-host"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp_reserved_address.test",
						tfjsonpath.New("enabled"),
						knownvalue.Bool(false),
					),
				},
			},
		},
	})
}

func testAccDHCPReservedAddressConfig(endpoint, macAddress, ipAddress, hostname string, enabled bool) string {
	return fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_dhcp_reserved_address" "test" {
  mac_address = %[2]q
  ip_address  = %[3]q
  hostname    = %[4]q
  enabled     = %[5]t
}
`, endpoint, macAddress, ipAddress, hostname, enabled)
}
