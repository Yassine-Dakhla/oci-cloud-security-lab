# HTTPS and TLS

## Certificate strategy

The public service uses a Let's Encrypt certificate obtained with Certbot for the server's public IP address.

The ACME HTTP challenge is served from:

```text
/var/www/certbot/.well-known/acme-challenge/
```

Nginx keeps that path available over HTTP so certificate validation and renewal can succeed.

## Nginx TLS termination

The host Nginx process handles TLS on port 443 and proxies decrypted HTTP traffic to the private Docker service on localhost.

```text
Client HTTPS
   ↓
Nginx :443
   ↓
127.0.0.1:8080
   ↓
Docker application
```

The Docker container does not need direct access to certificate private keys.

## HTTP redirect

Normal HTTP requests on port 80 are redirected to HTTPS.

The ACME challenge path is excluded from that redirect so Certbot can continue using HTTP validation.

## Certificate files

The live certificate is referenced from Certbot-managed paths under:

```text
/etc/letsencrypt/live/<PUBLIC_IP>/
```

The real certificate and private key are intentionally **not** included in this repository.

## Renewal

Because IP certificates are short-lived, renewal must be automated.

A Certbot deploy hook validates the Nginx configuration and reloads Nginx after a successful renewal:

```sh
#!/bin/sh
/usr/sbin/nginx -t && /bin/systemctl reload nginx
```

The renewal process was tested with:

```bash
sudo certbot renew --dry-run --run-deploy-hooks
```

The simulation completed successfully.

## Validation

External checks include:

```bash
curl -I http://<PUBLIC_IP>
curl -I https://<PUBLIC_IP>
nmap -Pn -p 80,443 <PUBLIC_IP>
```

Expected behavior:

- HTTP returns a redirect to HTTPS.
- HTTPS returns the application response.
- TCP/443 is open externally.
