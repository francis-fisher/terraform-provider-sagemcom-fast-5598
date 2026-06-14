resource "sagemcom_dhcp_reserved_address" "example" {
  mac_address = "00:11:22:33:44:55"
  ip_address  = "192.168.1.100"
  hostname    = "my-laptop"
  enabled     = true
}
