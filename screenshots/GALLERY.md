# Project Screenshot Gallery

The screenshots in this folder are sanitized before publication. Public IP addresses, OCI OCIDs, browser resource URLs, and unrelated browser-tab information are redacted where applicable.

| Screenshot | What it demonstrates |
|---|---|
| `00-website-http-redacted.png` | Initial HTTP web service state |
| `01-oci-subnet-redacted.png` | OCI public subnet configuration |
| `02-oci-instance-redacted.png` | Ubuntu 24.04 ARM64 compute instance |
| `03-oci-security-list-redacted.png` | OCI ingress rules for SSH, HTTP and HTTPS |
| `04-host-iptables.png` | Host firewall inspection / troubleshooting |
| `05-fail2ban-sshd.png` | Active Fail2Ban SSH jail |
| `06-docker-private-port.png` | Docker web service bound to `127.0.0.1:8080` |
| `07-external-nmap-redacted.png` | External port-scan evidence captured during firewall testing |
| `08-certbot-certificate-redacted.png` | Valid Let's Encrypt certificate configuration |
| `09-website-https-redacted.png` | Final HTTPS-enabled web service |

> Note: the HTTP/HTTPS website screenshots were captured before the page text was updated to replace the earlier UFW label with the final OCI Ubuntu `iptables` firewall design. The technical firewall documentation in `docs/04-firewall-security.md` reflects the final configuration.
