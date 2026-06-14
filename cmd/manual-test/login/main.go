package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-provider-scaffolding-framework/internal/client"
)

func main() {
	host := os.Getenv("SAGEMCOM_HOST")
	username := os.Getenv("SAGEMCOM_USERNAME")
	password := os.Getenv("SAGEMCOM_PASSWORD")

	if host == "" || username == "" || password == "" {
		fmt.Println("Error: Missing required environment variables.")
		fmt.Println("Please set:")
		fmt.Println("  SAGEMCOM_HOST      - Router IP address")
		fmt.Println("  SAGEMCOM_USERNAME  - Router admin username")
		fmt.Println("  SAGEMCOM_PASSWORD  - Router admin password")
		os.Exit(1)
	}

	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "http://" + host
	}

	fmt.Printf("Connecting to Sagemcom router at %s as '%s'...\n", host, username)
	c, err := client.NewClient(host, username, password)
	if err != nil {
		fmt.Printf("Error initializing client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	err = c.Login(ctx)
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nSuccessfully authenticated!")
	fmt.Println("--- Metadata Captured from /api/v1/open ---")
	fmt.Printf("Internal Firmware Version: %s\n", c.InternalFirmwareVersion)
	fmt.Printf("External Firmware Version: %s\n", c.ExternalFirmwareVersion)
	fmt.Printf("Serial Number:             %s\n", c.SerialNumber)
	fmt.Printf("Gateway IP:                %s\n", c.GatewayIP)
}
