// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/francis-fisher/terraform-provider-sagemcom-fast-5598/internal/client"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

type mockDHCPRouter struct {
	mu      sync.Mutex
	dhcp    client.DHCPServer
	dnsIPv4 client.DNSData
	dnsIPv6 client.DNSData
}

func newMockDHCPRouter() *mockDHCPRouter {
	return &mockDHCPRouter{
		dhcp: client.DHCPServer{
			Enable:     true,
			MinAddress: "192.168.1.5",
			MaxAddress: "192.168.1.250",
			LeaseTime:  43200,
			IPRouter:   "192.168.1.1",
			SubnetMask: "255.255.255.0",
		},
		dnsIPv4: client.DNSData{
			Interface: "LAN",
			DNSMode:   "DYNAMIC",
			Static: client.DNSStatic{
				ProviderList: "Custom",
				Provider:     "Custom",
				Servers:      "",
			},
		},
		dnsIPv6: client.DNSData{
			Interface: "",
			DNSMode:   "DYNAMIC",
			Static: client.DNSStatic{
				ProviderList: "",
				Provider:     "Custom",
				Servers:      "",
			},
		},
	}
}

func (m *mockDHCPRouter) Handler() http.Handler {
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
		http.SetCookie(w, &http.Cookie{Name: "salt", Value: "Q9Sn4I/gmeDMa9Z", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "nonce", Value: "88810e86271207f591c8f82aa3f58622", Path: "/"})
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/api/v1/dhcp", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			wrapper := []client.DHCPServerWrapper{
				{
					Hostname: "mygateway",
					DHCP:     m.dhcp,
				},
			}
			_ = json.NewEncoder(w).Encode(wrapper)
			return
		}

		if r.Method == http.MethodPut {
			_ = r.ParseForm()
			m.dhcp.Enable = r.Form.Get("enable") == "1"
			m.dhcp.MinAddress = r.Form.Get("minaddress")
			m.dhcp.MaxAddress = r.Form.Get("maxaddress")
			leaseVal, _ := strconv.Atoi(r.Form.Get("leasetime"))
			m.dhcp.LeaseTime = leaseVal
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/v1/dns/ipv4", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			wrapper := []client.DNSWrapper{
				{
					DNS: m.dnsIPv4,
				},
			}
			_ = json.NewEncoder(w).Encode(wrapper)
			return
		}

		if r.Method == http.MethodPut {
			_ = r.ParseForm()
			enableStatic := r.Form.Get("enableStatic") == "1"
			if enableStatic {
				m.dnsIPv4.DNSMode = "STATIC"
			} else {
				m.dnsIPv4.DNSMode = "DYNAMIC"
			}
			m.dnsIPv4.Static.Servers = r.Form.Get("servers")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/v1/dns/ipv6", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			wrapper := []client.DNSWrapper{
				{
					DNS: m.dnsIPv6,
				},
			}
			_ = json.NewEncoder(w).Encode(wrapper)
			return
		}

		if r.Method == http.MethodPut {
			_ = r.ParseForm()
			enableStatic := r.Form.Get("enableStatic") == "1"
			if enableStatic {
				m.dnsIPv6.DNSMode = "STATIC"
			} else {
				m.dnsIPv6.DNSMode = "DYNAMIC"
			}
			m.dnsIPv6.Static.Servers = r.Form.Get("servers")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	return mux
}

func TestAccDHCPResource(t *testing.T) {
	mockServer := newMockDHCPRouter()
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. Create with defaults (DHCP / dynamic DNS)
			{
				Config: testAccDHCPConfigDefaults(server.URL, "192.168.1.10", "192.168.1.200"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("id"),
						knownvalue.StringExact("dhcp"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("enable_dhcp"),
						knownvalue.Bool(true),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("min_address"),
						knownvalue.StringExact("192.168.1.10"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("max_address"),
						knownvalue.StringExact("192.168.1.200"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("lease_time"),
						knownvalue.Int64Exact(43200),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv4_mode"),
						knownvalue.StringExact("DHCP"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv6_mode"),
						knownvalue.StringExact("DHCP"),
					),
				},
			},
			// 2. ImportState testing
			{
				ResourceName:      "sagemcom_dhcp.test",
				ImportState:       true,
				ImportStateId:     "dhcp",
				ImportStateVerify: true,
			},
			// 3. Update to STATIC DNS (both v4 and v6) and disabled server
			{
				Config: testAccDHCPConfigStatic(server.URL, "192.168.1.20", "192.168.1.150", 86400, false, "198.51.100.5,198.51.100.6", "2001:db8:1::4::16:5,2001:db8:1::4::16:6"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("enable_dhcp"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("min_address"),
						knownvalue.StringExact("192.168.1.20"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("max_address"),
						knownvalue.StringExact("192.168.1.150"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("lease_time"),
						knownvalue.Int64Exact(86400),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv4_mode"),
						knownvalue.StringExact("STATIC"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv4_servers"),
						knownvalue.ListExact([]knownvalue.Check{
							knownvalue.StringExact("198.51.100.5"),
							knownvalue.StringExact("198.51.100.6"),
						}),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv6_mode"),
						knownvalue.StringExact("STATIC"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv6_servers"),
						knownvalue.ListExact([]knownvalue.Check{
							knownvalue.StringExact("2001:db8:1::4::16:5"),
							knownvalue.StringExact("2001:db8:1::4::16:6"),
						}),
					),
				},
			},
		},
	})
}

func TestAccDHCPResource_InvalidDNSCount(t *testing.T) {
	mockServer := newMockDHCPRouter()
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. 3 servers should fail (v4)
			{
				Config: fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_dhcp" "test" {
  min_address      = "192.168.1.10"
  max_address      = "192.168.1.200"
  dns_ipv4_mode    = "STATIC"
  dns_ipv4_servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
}
`, server.URL),
				ExpectError: regexp.MustCompile("dns_ipv4_servers must contain 1 or 2 DNS servers"),
			},
			// 2. 3 servers should fail (v6)
			{
				Config: fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_dhcp" "test" {
  min_address      = "192.168.1.10"
  max_address      = "192.168.1.200"
  dns_ipv6_mode    = "STATIC"
  dns_ipv6_servers = ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
}
`, server.URL),
				ExpectError: regexp.MustCompile("dns_ipv6_servers must contain 1 or 2 DNS servers"),
			},
			// 3. 1 server should succeed (v4 & v6)
			{
				Config: fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_dhcp" "test" {
  min_address      = "192.168.1.10"
  max_address      = "192.168.1.200"
  dns_ipv4_mode    = "STATIC"
  dns_ipv4_servers = ["1.1.1.1"]
  dns_ipv6_mode    = "STATIC"
  dns_ipv6_servers = ["2001:db8::1"]
}
`, server.URL),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv4_mode"),
						knownvalue.StringExact("STATIC"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv4_servers"),
						knownvalue.ListExact([]knownvalue.Check{
							knownvalue.StringExact("1.1.1.1"),
						}),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv6_mode"),
						knownvalue.StringExact("STATIC"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv6_servers"),
						knownvalue.ListExact([]knownvalue.Check{
							knownvalue.StringExact("2001:db8::1"),
						}),
					),
				},
			},
			// 4. Omitted servers under STATIC should fail (v4)
			{
				Config: fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_dhcp" "test" {
  min_address      = "192.168.1.10"
  max_address      = "192.168.1.200"
  dns_ipv4_mode    = "STATIC"
}
`, server.URL),
				ExpectError: regexp.MustCompile("dns_ipv4_servers must be configured when dns_ipv4_mode is 'STATIC'"),
			},
			// 5. Empty list servers under STATIC should fail (v4)
			{
				Config: fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_dhcp" "test" {
  min_address      = "192.168.1.10"
  max_address      = "192.168.1.200"
  dns_ipv4_mode    = "STATIC"
  dns_ipv4_servers = []
}
`, server.URL),
				ExpectError: regexp.MustCompile("dns_ipv4_servers must contain 1 or 2 DNS servers"),
			},
			// 6. Empty list servers under DHCP should succeed (v4 & v6)
			{
				Config: fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_dhcp" "test" {
  min_address      = "192.168.1.10"
  max_address      = "192.168.1.200"
  dns_ipv4_mode    = "DHCP"
  dns_ipv4_servers = []
  dns_ipv6_mode    = "DHCP"
  dns_ipv6_servers = []
}
`, server.URL),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv4_mode"),
						knownvalue.StringExact("DHCP"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_dhcp.test",
						tfjsonpath.New("dns_ipv6_mode"),
						knownvalue.StringExact("DHCP"),
					),
				},
			},
		},
	})
}

func testAccDHCPConfigDefaults(endpoint, minAddr, maxAddr string) string {
	return fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_dhcp" "test" {
  min_address = %[2]q
  max_address = %[3]q
}
`, endpoint, minAddr, maxAddr)
}

func testAccDHCPConfigStatic(endpoint, minAddr, maxAddr string, lease int, enableServer bool, dns4Servers, dns6Servers string) string {
	v4Slice := strings.Split(dns4Servers, ",")
	v6Slice := strings.Split(dns6Servers, ",")
	return fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_dhcp" "test" {
  min_address      = %[2]q
  max_address      = %[3]q
  lease_time       = %[4]d
  enable_dhcp      = %[5]t
  dns_ipv4_mode    = "STATIC"
  dns_ipv4_servers = [%[6]q, %[7]q]
  dns_ipv6_mode    = "STATIC"
  dns_ipv6_servers = [%[8]q, %[9]q]
}
`, endpoint, minAddr, maxAddr, lease, enableServer, v4Slice[0], v4Slice[1], v6Slice[0], v6Slice[1])
}
