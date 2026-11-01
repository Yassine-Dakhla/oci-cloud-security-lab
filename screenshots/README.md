# Project Screenshots

These screenshots provide visual evidence of the OCI Cloud Security Lab build. Sensitive details that were not required for the portfolio demonstration were redacted before publication.

## Published evidence

| File | What it demonstrates |
|---|---|
| `01-oci-subnet-redacted.png` | OCI subnet and VCN configuration |
| `02-oci-instance-redacted.png` | Running OCI compute instance |
| `03-oci-security-list-redacted.png` | Cloud-level ingress controls |
| `04-host-iptables.png` | Ubuntu host firewall rules |
| `05-fail2ban-sshd.png` | Active Fail2Ban SSH jail |
| `06-docker-private-port.png` | Docker service bound to `127.0.0.1:8080` |
| `08-certbot-certificate-redacted.png` | Valid Certbot-managed TLS certificate |
| `09-website-https-redacted.png` | Final website served over HTTPS |

The files are stored in:

```text
screenshots/oci-cloud-security-sanitized-screenshots/
```

`00-website-http-redacted.png` is retained as historical evidence from the earlier HTTP stage of the build, before the final HTTPS configuration.

## Redaction policy

Before screenshots are published, check for and remove unnecessary sensitive information such as:

- public IP addresses when they do not need to be shown
- complete OCI OCIDs
- private SSH keys
- API keys and tokens
- passwords
- personal email addresses
- certificate private-key paths or other secret material

Redaction should hide sensitive values without changing the technical result being demonstrated.