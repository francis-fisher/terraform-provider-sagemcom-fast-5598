Automatic tests which don't connect to a physical router but use mocking strategies can be run as follows:

`$ go test -v ./internal/client/...`

There are also some manual tests which connect to a router and can be run as follows:

# 1 - Login

`SAGEMCOM_HOST=192.168.1.1 SAGEMCOM_USER=admin SAGECOM_PASSWORD=asdasdj go run cmd/manual-test/login/main.go`
