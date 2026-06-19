resource "sagemcom_dhcp" "example" {
  enable_dhcp = true
  min_address = "192.168.1.10"
  max_address = "192.168.1.250"
  lease_time  = 43200
  # mode can be either "DHCP" in which case the router will advertise the ISP's DNS servers,
  # or STATIC, in which case the router will advertise the DNS servers provided by the user
  dns_ipv4_mode    = "STATIC"
  dns_ipv4_servers = ["1.1.1.1", "8.8.8.8"]
  dns_ipv6_mode    = "DHCP"
  dns_ipv6_servers = []
}
