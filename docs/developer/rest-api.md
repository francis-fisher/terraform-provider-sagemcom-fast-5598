# Sagemcom F@st REST API Reference

This document catalogs the reverse-engineered REST API endpoints for the Sagemcom F@st 5598 router (under the YouFibre customized firmware). 

All requests are served over HTTP.

---

## Authentication Endpoints

### 1. GET `/api/v1/open`
* **Authentication**: None
* **Description**: Returns public router metadata. Crucially, this endpoint initializes the connection session by setting the connection ID (`conid`) and initial dummy salt/nonce cookies.
* **Response Headers**:
  ```http
  Set-Cookie: conid=f8d4556856b1eaa6598cda39d8e607ba; Max-Age=900; Path=/; HttpOnly; Version=1; samesite=Strict
  Set-Cookie: nonce=0; Path=/
  Set-Cookie: salt=0; Path=/
  ```
* **Response Body (JSON)**:
  ```json
  [
    {
      "wan_status": "Up",
      "time": "2026-06-14T13:49:21",
      "serial": "N726061A2000613",
      "external_firmware_version": "SGQB320000205",
      "internal_firmware_version": "sw2024.07.205_Prod",
      "uptime": "3095",
      "gateway_ip": "192.168.1.1",
      "firmware": "SGQB320000205",
      "serial_number": "N726061A2000613",
      "wan_ipv4": "203.0.113.145"
    }
  ]
  ```

### 2. POST `/api/v1/login-params`
* **Authentication**: None (Requires initial `conid` cookie in request headers)
* **Description**: Requests the cryptographic salt and nonce challenge required to generate the password signature for the specified user.
* **Request Body** (`application/x-www-form-urlencoded`):
  ```
  login=admin
  ```
* **Response Headers**:
  ```http
  Set-Cookie: conid=39e39a8e657f75de482447e505685656; Max-Age=900; Path=/; HttpOnly; Version=1; samesite=Strict
  Set-Cookie: nonce=88810e86271207f591c8f82aa3f58622; Path=/
  Set-Cookie: salt=Q9Sn4I/gmeDMa9Z; Path=/
  ```
* **Response Status**: `204 No Content`

### 3. POST `/api/v1/login`
* **Authentication**: None (Requires `conid`, `nonce`, and `salt` cookies returned from `/api/v1/login-params` in request headers)
* **Description**: Submits the cryptographic verification payload to establish an authenticated session.
* **Request Body** (`application/x-www-form-urlencoded`):
  ```
  login=admin&auth_key=eae98afd5aec4bf29b...&cnonce=6783452008529600000
  ```
* **Response Headers**:
  ```http
  Set-Cookie: conid=5f38e8fe50cb440f5432427d9e2a1b2d; Max-Age=600; Path=/; HttpOnly; Version=1; samesite=Strict
  Set-Cookie: nonce=b7e006990e6db39d922fe82eeb90f9ed; Path=/
  Set-Cookie: salt=Q9Sn4I/gmeDMa9Z; Path=/
  ```
* **Response Status**: `204 No Content` (Successful authentication overrides the `conid` cookie with the actual persistent session token).

---

## DHCP Reserved Addresses

### 1. GET `/api/v1/dhcp/clients`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Lists all currently configured static DHCP lease reservations.
* **Response Body (JSON)**:
  ```json
  [
    {
      "dhcp": {
        "clients": [
          {
            "id": 1,
            "hostname": "sample",
            "ipaddress": "192.168.1.6",
            "macaddress": "02:00:00:00:00:01",
            "enable": true
          }
        ]
      }
    }
  ]
  ```

### 2. POST `/api/v1/dhcp/clients`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Creates a new static DHCP address reservation.
* **Request Body** (`application/x-www-form-urlencoded`):
  ```
  enable=1&hostname=sample&macaddress=02%3A00%3A00%3A00%3A00%3A04&ipaddress=192.168.1.5
  ```
  * `enable`: `1` (enabled) or `0` (disabled).
  * `hostname`: Friendly hostname for the reservation.
  * `macaddress`: MAC address of the target client.
  * `ipaddress`: Static IP address reservation.
* **Response Status**: `204 No Content` (Does not return the newly assigned `id`. The client must list all clients afterward and filter by MAC/IP to discover the resource's `id`).

### 3. PUT `/api/v1/dhcp/clients/{id}`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Modifies an existing static DHCP reservation. The endpoint supports partial updates (i.e. sending only a subset of fields like just `macaddress` or just `hostname` and `ipaddress`).
* **Request Body** (`application/x-www-form-urlencoded`):
  ```
  hostname=mobile-client&ipaddress=192.168.1.19
  ```
  *(Or: `macaddress=02:00:00:00:00:13`)*
* **Response Status**: 
  * `204 No Content`: Successful update.
  * `400 Bad Request`: Validation failure. Has been observed when trying to assign an IP address that conflicts with an active/stale dynamic DHCP lease for another mac address..
    * *Note on Router UI Bug*: Interestingly, the router's web UI does not handle this `400` response. If you perform this conflicting update in the browser, the UI will report that the reservation was changed successfully, but reloading the page reveals that the original value was retained.

### 4. DELETE `/api/v1/dhcp/clients/{id}`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Deletes a static DHCP reservation by its assigned ID.
* **Response Status**: `204 No Content`

---

## System Telemetry & Status

### 1. GET `/api/v2/home`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Retrieves general status about client connections (Wi-Fi, Ethernet), active SSIDs (including plaintext passwords), and the product hardware model.
* **Note**: This endpoint has a high latency overhead (approx. **3 seconds**) because it triggers multiple underlying hardware system queries. It should be queried sparingly.
* **Response Body (JSON)**:
  ```json
  [
    {
      "wirelessListDevice": [
        {
          "macAddress": "02:00:00:00:00:02",
          "ipv4Address": "192.168.1.12",
          "hostName": "smart-tv-client",
          "linkDevices": [
            {
              "band": "2.4",
              "rate": "58500",
              "rssi0": "78"
            }
          ]
        }
      ],
      "ssids": [
        {
          "radio": "5GHZ",
          "type": "Primary",
          "ssidName": "TestSSID",
          "password": "dummy_password",
          "protocol": "WPA2_WPA3_PERSONAL"
        }
      ],
      "productClass": "FAST5598"
    }
  ]
  ```

### 2. GET `/api/v1/device/features`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Lists active software modules and features enabled on the router (GPON, VoIP, firewall custom settings, etc.).

### 3. GET `/api/v1/wan/ipv4`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Returns detailed IPv4 network settings for the WAN uplink interface (addressing type, WAN mode, gateway, MAC, uptime, status, MTU, etc.).

---

## NAT & Port Forwarding

### 1. GET `/api/v1/nat/rules`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Lists all currently configured IPv4 port forwarding / NAT rules.
* **Response Body (JSON)**:
  ```json
  [
    {
      "nat": {
        "enable": true,
        "rules": [
          {
            "id": 1,
            "enable": true,
            "description": "ssh",
            "externalIP": "",
            "externalPort": 22,
            "externalEndPort": 0,
            "internalPort": 22,
            "internalIP": "192.168.1.10",
            "service": "OTHER",
            "protocol": "tcp"
          }
        ]
      }
    }
  ]
  ```

### 2. POST `/api/v1/nat/rules`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Creates a new port forwarding rule.
* **Request Body** (`application/x-www-form-urlencoded`):
  ```
  enable=1&description=ssh&service=OTHER&protocol=tcp&ipremote=*&ipaddress=192.168.1.10&externalPort=2222&internalPort=22&externalEndPort=0
  ```
  * `enable`: `1` (enabled) or `0` (disabled).
  * `description`: Descriptive name or label.
  * `service`: Typically defaulted to `OTHER`.
  * `protocol`: The transport or network protocol. Supported protocol API values (and their corresponding UI labels) are:
    * `all` (UI Label: `TCP - UDP`)
    * `tcp` (UI Label: `TCP`)
    * `udp` (UI Label: `UDP`)
    * `both` (UI Label: `BOTH`)
    * `icmp` (UI Label: `ICMP`)
    * `gre` (UI Label: `GRE`)
    * `ah` (UI Label: `AH`)
    * `esp` (UI Label: `ESP`)
    * `other` (UI Label: `Other`)
  * `ipremote`: External IP address allowed to access (or `*` to allow any IP address). Maps to `externalIP` in GET responses.
  * `ipaddress`: Local IP address of the target machine on the LAN. Maps to `internalIP` in GET responses.
  * `externalPort`: Starting external port number.
  * `internalPort`: Local port number.
  * `externalEndPort`: Ending external port number (set to `0` if forwarding a single port, or a higher number to forward a range of ports).
* **Response Status**: `204 No Content` (Does not return the newly assigned `id`. The client must list all rules afterward and filter by matching attributes like description, IP address, external port, and protocol to discover the rule's `id`).

### 3. PUT `/api/v1/nat/rules/{id}`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Modifies an existing port forwarding rule.
* **Request Body** (`application/x-www-form-urlencoded`):
  ```
  enable=1&description=ssh-updated&protocol=tcp&ipaddress=192.168.1.10&externalPort=22&internalPort=22&externalEndPort=0&ipremote=198.51.100.1
  ```
  * `ipremote`: Set to `*` to allow traffic from any external remote source IP, or a specific IP address to restrict access.
* **Response Status**:
  * `204 No Content`: Successful update.
  * `400 Bad Request`: May occur under certain conditions or when changing critical ports or protocols depending on connection/firmware state. To avoid bad requests, it is recommended to delete and recreate rules if key routing attributes (IP address, ports, protocol) are changed.

### 4. DELETE `/api/v1/nat/rules/{id}`
* **Authentication**: Required (`conid` session cookie)
* **Description**: Deletes a port forwarding rule by its assigned ID.
* **Response Status**: `204 No Content`


