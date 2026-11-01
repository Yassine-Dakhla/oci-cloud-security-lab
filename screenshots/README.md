# Screenshot Checklist

Add screenshots here only after checking that they do not reveal secrets, private keys, API tokens, full OCI OCIDs, email addresses, or other sensitive information.

Recommended portfolio screenshots:

1. OCI VCN overview with resource IDs cropped/redacted.
2. Public and private subnet list.
3. Compute instance summary showing Ubuntu, ARM64/Ampere shape, CPU, and RAM without exposing unnecessary identifiers.
4. External Nmap validation showing ports 22, 80, and 443 open while 8080 remains filtered.
5. Browser view of the OCI Cloud Security Lab page over HTTPS.
6. Fail2Ban SSH jail status with any external IP addresses redacted.
7. Docker container status showing `127.0.0.1:8080->80/tcp`.

Suggested filenames:

```text
01-vcn-overview.png
02-subnets.png
03-compute-instance.png
04-external-port-scan.png
05-https-web-page.png
06-fail2ban-status.png
07-docker-private-binding.png
```
