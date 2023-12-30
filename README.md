## GoWVServe
Go implementation of PyWidevine serve

### Usage
```bash
go run serve.go
```
or just run the binary
```bash
./gowvserve
```

### Requirements
- [Go](https://golang.org/)

### Sample config
```yaml
serve:
  port: 9000
  host: 127.0.0.1
  mode: production
  force_privacy_mode: true

users:
  thisissecretkey:
    name: example
    devices:
      - test

devices:
  - "./devices/test.wvd"
```

### Thanks to :
- [GoWidevine](https://github.com/iyear/gowidevine)
- [PyWidevine](https://github.com/devine-dl/pywidevine)
