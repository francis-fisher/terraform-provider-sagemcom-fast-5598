package client

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
)

// Client handles interaction with the Sagemcom Fast 5598 router API.
type Client struct {
	BaseURL    string
	Username   string
	Password   string
	HTTPClient *http.Client

	// Router metadata populated during Login
	InternalFirmwareVersion string
	ExternalFirmwareVersion string
	SerialNumber            string
	ProductClass            string
	GatewayIP               string
}

// OpenResponse represents the metadata structure returned by /api/v1/open.
type OpenResponse struct {
	InternalFirmwareVersion string `json:"internal_firmware_version"`
	ExternalFirmwareVersion string `json:"external_firmware_version"`
	SerialNumber            string `json:"serial_number"`
	GatewayIP               string `json:"gateway_ip"`
}

// HomeResponse represents the metadata structure returned by /api/v2/home.
type HomeResponse struct {
	ProductClass string `json:"productClass"`
}

// NewClient initializes a new Client with a cookie jar for session storage.
func NewClient(baseURL, username, password string) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	baseURL = strings.TrimSuffix(baseURL, "/")

	httpClient := &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
	}

	return &Client{
		BaseURL:    baseURL,
		Username:   username,
		Password:   password,
		HTTPClient: httpClient,
	}, nil
}

// Computes the SHA-512 hex digest of a string.
func sha512Hex(s string) string {
	h := sha512.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// Generates a random 19-digit decimal string.
func generateCnonce() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// A 19-digit number starts from 1000000000000000000 up to 9999999999999999999.
	// Math.random()*1e19 can be padded up to 19 characters.
	val := r.Uint64() % 10000000000000000000
	return fmt.Sprintf("%019d", val)
}

// computeAuthKey calculates the login auth_key using SHA-512 Crypt and SHA-512 hex digests.
func (c *Client) computeAuthKey(nonce, salt, cnonce string) (string, error) {
	crypter := crypt.SHA512.New()
	cryptSalt := "$6$" + salt

	// Generate standard UNIX sha512_crypt hash
	cryptHash, err := crypter.Generate([]byte(c.Password), []byte(cryptSalt))
	if err != nil {
		return "", fmt.Errorf("failed to compute sha512_crypt: %w", err)
	}

	// cryptHash is in format: $6$salt$hash, but sagemcom doesn't want $6$
	if !strings.HasPrefix(cryptHash, "$6$") {
		return "", fmt.Errorf("invalid sha512_crypt output prefix: %s", cryptHash)
	}
	trimmedHash := strings.TrimPrefix(cryptHash, "$6$")

	usernameHash := sha512Hex(c.Username + ":" + nonce + ":" + trimmedHash)

	authKey := sha512Hex(usernameHash + ":0:" + cnonce)

	return authKey, nil
}

// Login authenticates against the Sagemcom Fast 5598 API.
func (c *Client) Login(ctx context.Context) error {
	// Fetch metadata from /api/v1/open (including session cookie)
	_ = c.fetchMetadata(ctx)

	// POST /api/v1/login-params to get salt and nonce
	loginParamsURL := fmt.Sprintf("%s/api/v1/login-params", c.BaseURL)
	form := url.Values{}
	form.Set("login", c.Username)

	req, err := http.NewRequestWithContext(ctx, "POST", loginParamsURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create login-params request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("login-params request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("login-params response status %d, expected 204", resp.StatusCode)
	}

	// Extract salt and nonce cookies
	parsedURL, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	cookies := c.HTTPClient.Jar.Cookies(parsedURL)

	var salt, nonce string
	for _, cookie := range cookies {
		switch cookie.Name {
		case "salt":
			salt = cookie.Value
		case "nonce":
			nonce = cookie.Value
		}
	}

	if salt == "" || nonce == "" {
		return errors.New("failed to retrieve salt or nonce from login-params cookies")
	}

	// Compute auth_key
	cnonce := generateCnonce()
	authKey, err := c.computeAuthKey(nonce, salt, cnonce)
	if err != nil {
		return fmt.Errorf("failed to compute auth_key: %w", err)
	}

	// POST /api/v1/login to establish the authenticated session
	loginURL := fmt.Sprintf("%s/api/v1/login", c.BaseURL)
	loginForm := url.Values{}
	loginForm.Set("login", c.Username)
	loginForm.Set("auth_key", authKey)
	loginForm.Set("cnonce", cnonce)

	loginReq, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(loginForm.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	loginResp, err := c.HTTPClient.Do(loginReq)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("login response status %d, expected 204", loginResp.StatusCode)
	}

	return nil
}

// fetchMetadata retrieves router info from the open endpoint.
func (c *Client) fetchMetadata(ctx context.Context) error {
	openURL := fmt.Sprintf("%s/api/v1/open", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", openURL, nil)
	if err != nil {
		return err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata fetch response status %d, expected 200", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var openResp []OpenResponse
	err = json.Unmarshal(bodyBytes, &openResp)
	if err != nil {
		return err
	}

	if len(openResp) > 0 {
		c.InternalFirmwareVersion = openResp[0].InternalFirmwareVersion
		c.ExternalFirmwareVersion = openResp[0].ExternalFirmwareVersion
		c.SerialNumber = openResp[0].SerialNumber
		c.GatewayIP = openResp[0].GatewayIP
	}

	return nil
}

// fetchHomeMetadata retrieves post-login home metadata such as product class (i.e. the router model, but nothing that identifies any ISP customisation).
func (c *Client) fetchHomeMetadata(ctx context.Context) error {
	body, err := c.AuthenticatedGet(ctx, "/api/v2/home")
	if err != nil {
		return err
	}

	var homeResp []HomeResponse
	err = json.Unmarshal(body, &homeResp)
	if err != nil {
		return err
	}

	if len(homeResp) > 0 {
		c.ProductClass = homeResp[0].ProductClass
	}

	return nil
}

// AuthenticatedGet executes a GET request using session cookies.
func (c *Client) AuthenticatedGet(ctx context.Context, path string) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/%s", c.BaseURL, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned status %d", path, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// AuthenticatedPost executes a urlencoded POST request using session cookies.
func (c *Client) AuthenticatedPost(ctx context.Context, path string, data url.Values) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/%s", c.BaseURL, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Some POST endpoints might return 204 (No Content) or 200 (OK)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("POST %s returned status %d", path, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// AuthenticatedPut executes a urlencoded PUT request using session cookies.
func (c *Client) AuthenticatedPut(ctx context.Context, path string, data url.Values) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/%s", c.BaseURL, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, "PUT", reqURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("PUT %s returned status %d", path, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// AuthenticatedDelete executes a DELETE request using session cookies.
func (c *Client) AuthenticatedDelete(ctx context.Context, path string) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/%s", c.BaseURL, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, "DELETE", reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("DELETE %s returned status %d", path, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// DHCPClient represents a reserved address on the router.
type DHCPClient struct {
	ID         int    `json:"id"`
	Hostname   string `json:"hostname"`
	IPAddress  string `json:"ipaddress"`
	MACAddress string `json:"macaddress"`
	Enabled    bool   `json:"enable"`
}

type DHCPClientsWrapper struct {
	DHCP struct {
		Clients []DHCPClient `json:"clients"`
	} `json:"dhcp"`
}

// GetDHCPReservedAddresses retrieves all reserved DHCP leases.
func (c *Client) GetDHCPReservedAddresses(ctx context.Context) ([]DHCPClient, error) {
	body, err := c.AuthenticatedGet(ctx, "/api/v1/dhcp/clients")
	if err != nil {
		return nil, err
	}

	var wrappers []DHCPClientsWrapper
	if err := json.Unmarshal(body, &wrappers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DHCP clients: %w", err)
	}

	if len(wrappers) > 0 {
		return wrappers[0].DHCP.Clients, nil
	}

	return []DHCPClient{}, nil
}

// AddDHCPReservedAddress creates a new DHCP reservation on the router.
// Returns the newly created DHCPClient with its assigned ID.
func (c *Client) AddDHCPReservedAddress(ctx context.Context, hostname, macaddress, ipaddress string, enabled bool) (*DHCPClient, error) {
	form := url.Values{}
	enableVal := "0"
	if enabled {
		enableVal = "1"
	}
	form.Set("enable", enableVal)
	form.Set("hostname", hostname)
	form.Set("macaddress", macaddress)
	form.Set("ipaddress", ipaddress)

	_, err := c.AuthenticatedPost(ctx, "/api/v1/dhcp/clients", form)
	if err != nil {
		return nil, fmt.Errorf("failed to add DHCP reserved address: %w", err)
	}

	// Since the POST response does not return the new ID, we query the list
	// of clients and find the one that matches our MAC address to discover the ID.
	clients, err := c.GetDHCPReservedAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query DHCP clients after creation: %w", err)
	}

	// Search by MAC address (case-insensitive)
	targetMAC := strings.ToLower(macaddress)
	for _, client := range clients {
		if strings.ToLower(client.MACAddress) == targetMAC {
			return &client, nil
		}
	}

	return nil, fmt.Errorf("DHCP reservation was created, but could not be located in the clients list afterwards")
}

// DeleteDHCPReservedAddress deletes a DHCP reservation by ID.
func (c *Client) DeleteDHCPReservedAddress(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/v1/dhcp/clients/%d", id)
	_, err := c.AuthenticatedDelete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete DHCP reserved address %d: %w", id, err)
	}
	return nil
}

// UpdateDHCPReservedAddress updates an existing DHCP reservation.
// It accepts optional pointers for hostname, macaddress, ipaddress, and enabled.
// Only non-nil fields will be sent in the PUT request.
func (c *Client) UpdateDHCPReservedAddress(
	ctx context.Context,
	id int,
	hostname *string,
	macaddress *string,
	ipaddress *string,
	enabled *bool,
) error {
	form := url.Values{}
	if enabled != nil {
		enableVal := "0"
		if *enabled {
			enableVal = "1"
		}
		form.Set("enable", enableVal)
	}
	if hostname != nil {
		form.Set("hostname", *hostname)
	}
	if macaddress != nil {
		form.Set("macaddress", *macaddress)
	}
	if ipaddress != nil {
		form.Set("ipaddress", *ipaddress)
	}

	path := fmt.Sprintf("/api/v1/dhcp/clients/%d", id)
	_, err := c.AuthenticatedPut(ctx, path, form)
	if err != nil {
		return fmt.Errorf("failed to update DHCP reserved address %d: %w", id, err)
	}
	return nil
}
