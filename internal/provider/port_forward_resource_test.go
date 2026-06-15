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

type mockNATRouterServer struct {
	mu     sync.Mutex
	rules  map[int]client.PortForward
	nextID int
}

func newMockNATRouterServer() *mockNATRouterServer {
	return &mockNATRouterServer{
		rules:  make(map[int]client.PortForward),
		nextID: 1,
	}
}

func (m *mockNATRouterServer) Handler() http.Handler {
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

	ruleDetailRegex := regexp.MustCompile(`^/api/v1/nat/rules/(\d+)$`)

	mux.HandleFunc("/api/v1/nat/rules", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method == http.MethodGet {
			var ruleList []client.PortForward
			for _, rl := range m.rules {
				ruleList = append(ruleList, rl)
			}
			w.Header().Set("Content-Type", "application/json")
			wrapper := []client.NATRulesWrapper{}
			w1 := client.NATRulesWrapper{}
			w1.NAT.Enabled = true
			w1.NAT.Rules = ruleList
			wrapper = append(wrapper, w1)
			_ = json.NewEncoder(w).Encode(wrapper)
			return
		}

		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			enabled := r.Form.Get("enable") == "1"
			description := r.Form.Get("description")
			protocol := r.Form.Get("protocol")
			ip := r.Form.Get("ipaddress")
			ipremote := r.Form.Get("ipremote")
			if ipremote == "*" {
				ipremote = ""
			}
			extPort, _ := strconv.Atoi(r.Form.Get("externalPort"))
			intPort, _ := strconv.Atoi(r.Form.Get("internalPort"))
			extEndPort, _ := strconv.Atoi(r.Form.Get("externalEndPort"))

			id := m.nextID
			m.nextID++

			newRule := client.PortForward{
				ID:              id,
				Enabled:         enabled,
				Description:     description,
				ExternalIP:      ipremote,
				ExternalPort:    extPort,
				ExternalEndPort: extEndPort,
				InternalPort:    intPort,
				InternalIP:      ip,
				Service:         "OTHER",
				Protocol:        protocol,
			}
			m.rules[id] = newRule
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/v1/nat/rules/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		matches := ruleDetailRegex.FindStringSubmatch(r.URL.Path)
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
			rl, exists := m.rules[id]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Form.Get("enable") != "" {
				rl.Enabled = r.Form.Get("enable") == "1"
			}
			if r.Form.Get("description") != "" {
				rl.Description = r.Form.Get("description")
			}
			if r.Form.Get("protocol") != "" {
				rl.Protocol = r.Form.Get("protocol")
			}
			if r.Form.Get("ipaddress") != "" {
				rl.InternalIP = r.Form.Get("ipaddress")
			}
			if r.Form.Get("ipremote") != "" {
				remoteIP := r.Form.Get("ipremote")
				if remoteIP == "*" {
					rl.ExternalIP = ""
				} else {
					rl.ExternalIP = remoteIP
				}
			}
			if r.Form.Get("externalPort") != "" {
				rl.ExternalPort, _ = strconv.Atoi(r.Form.Get("externalPort"))
			}
			if r.Form.Get("internalPort") != "" {
				rl.InternalPort, _ = strconv.Atoi(r.Form.Get("internalPort"))
			}
			if r.Form.Get("externalEndPort") != "" {
				rl.ExternalEndPort, _ = strconv.Atoi(r.Form.Get("externalEndPort"))
			}
			m.rules[id] = rl
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method == http.MethodDelete {
			if _, exists := m.rules[id]; !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(m.rules, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	return mux
}

func TestAccPortForwardResource(t *testing.T) {
	mockServer := newMockNATRouterServer()
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. Create and Read testing
			{
				Config: testAccPortForwardConfig(server.URL, "bastion-ssh", "192.168.1.10", 2222, 22, 0, "tcp", true),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("id"),
						knownvalue.StringExact("1"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("description"),
						knownvalue.StringExact("bastion-ssh"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("local_ip_address"),
						knownvalue.StringExact("192.168.1.10"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("remote_ip_address"),
						knownvalue.StringExact("*"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("remote_port"),
						knownvalue.Int64Exact(2222),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("local_port"),
						knownvalue.Int64Exact(22),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("remote_end_port"),
						knownvalue.Int64Exact(0),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("protocol"),
						knownvalue.StringExact("tcp"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("enabled"),
						knownvalue.Bool(true),
					),
				},
			},
			// 2. ImportState testing
			{
				ResourceName:      "sagemcom_port_forward.test",
				ImportState:       true,
				ImportStateId:     "bastion-ssh",
				ImportStateVerify: true,
			},
			// 3. Update and Read testing (In-place update of description and enabled)
			{
				Config: testAccPortForwardConfig(server.URL, "updated-ssh-rule", "192.168.1.10", 2222, 22, 0, "tcp", false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("id"),
						knownvalue.StringExact("1"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("description"),
						knownvalue.StringExact("updated-ssh-rule"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("enabled"),
						knownvalue.Bool(false),
					),
				},
			},
		},
	})
}

func testAccPortForwardConfig(endpoint, description, ipAddress string, externalPort, internalPort, externalEndPort int, protocol string, enabled bool) string {
	return fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_port_forward" "test" {
  description     = %[2]q
  local_ip_address = %[3]q
  remote_port     = %[4]d
  local_port      = %[5]d
  remote_end_port = %[6]d
  protocol        = %[7]q
  enabled         = %[8]t
}
`, endpoint, description, ipAddress, externalPort, internalPort, externalEndPort, protocol, enabled)
}

func TestAccPortForwardResource_ImportDuplicateError(t *testing.T) {
	mockServer := newMockNATRouterServer()

	// Preload two rules with the exact same description
	mockServer.rules[1] = client.PortForward{
		ID:           1,
		Enabled:      true,
		Description:  "duplicate-desc",
		InternalIP:   "192.168.1.10",
		ExternalPort: 80,
		InternalPort: 80,
		Protocol:     "tcp",
	}
	mockServer.rules[2] = client.PortForward{
		ID:           2,
		Enabled:      true,
		Description:  "duplicate-desc",
		InternalIP:   "192.168.1.11",
		ExternalPort: 8080,
		InternalPort: 8080,
		Protocol:     "tcp",
	}
	mockServer.nextID = 3

	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_port_forward" "test" {
  description      = "duplicate-desc"
  local_ip_address = "192.168.1.10"
  remote_port      = 80
  local_port       = 80
  protocol         = "tcp"
}
`, server.URL),
			},
			{
				ResourceName:      "sagemcom_port_forward.test",
				ImportState:       true,
				ImportStateId:     "duplicate-desc",
				ExpectError:       regexp.MustCompile("cannot import as multiple entries have same description"),
				ImportStateVerify: false,
			},
		},
	})
}

func TestAccPortForwardResource_RemoteIP(t *testing.T) {
	mockServer := newMockNATRouterServer()
	server := httptest.NewServer(mockServer.Handler())
	defer server.Close()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
provider "sagemcom" {
  endpoint = %[1]q
  username = "admin"
  password = "some_secure_password"
}

resource "sagemcom_port_forward" "test" {
  description       = "specific remote ip"
  local_ip_address  = "192.168.1.30"
  remote_ip_address = "198.51.100.1"
  remote_port       = 100
  local_port        = 0
  protocol          = "both"
}
`, server.URL),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("local_ip_address"),
						knownvalue.StringExact("192.168.1.30"),
					),
					statecheck.ExpectKnownValue(
						"sagemcom_port_forward.test",
						tfjsonpath.New("remote_ip_address"),
						knownvalue.StringExact("198.51.100.1"),
					),
				},
			},
		},
	})
}
