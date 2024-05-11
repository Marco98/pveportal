# pveportal

[WIP] A reverse-proxy/portal service to quickly access multiple proxmox ve clusters.

## Overview

![screenshot of switcher](/docs/gui-switch.jpeg)

### Features / Ideas

- [x] hide nag-popup (please [purchase a licence](https://www.proxmox.com/en/proxmox-virtual-environment/pricing) for production)
- [x] switch clusters in GUI
- [x] pass-through authentication
- [ ] host health checks
- [ ] see resources cross-cluster

## Installation

### Download

Download the latest release [[>>HERE<<]](https://github.com/Marco98/pveportal/releases/latest)

## Configuration

WIP

### Example

```yaml
# server
listen_port: 8080
tls_cert_file: server.crt
tls_key_file: server.key
# hooks
hide_repowarn: true
passthroughauth: true
# connectivity
check_interval: 5
ignore_cert: true
username: svc_pveportal
password: insecure
# clusters
clusters:
  - name: dc01
    hosts:
      - name: pve1
        endpoint: https://192.168.1.10:8006
      - name: pve2
        endpoint: https://192.168.1.11:8006
  - name: dc02
    hosts:
      - name: pve1
        endpoint: https://192.168.2.10:8006
      - name: pve2
        endpoint: https://192.168.2.11:8006
  - name: dc03
    hosts:
      - name: pve1
        endpoint: https://192.168.3.10:8006
      - name: pve2
        endpoint: https://192.168.3.11:8006
```
