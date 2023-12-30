## GoWVServe
Go implementation of PyWidevine serve

### Usage
Put the `.wvd` files in the devices folder and run the gowvserve
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

## Disclaimer
This project is for research purposes only, the use of this code is your responsibility.

## Support
If you like my work, consider buying me a coffee :)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/devatadev)
