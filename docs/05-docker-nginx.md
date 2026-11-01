# Docker and Nginx

## Docker installation

Docker was installed on the Ubuntu ARM64 VM and verified with:

```bash
sudo docker version
```

The engine reported `linux/arm64`, matching the OCI Ampere compute architecture.

## Private application container

The demo web application runs in an Nginx Alpine container named:

```text
cyberlab-web
```

The important networking choice is:

```text
127.0.0.1:8080:80
```

instead of:

```text
0.0.0.0:8080:80
```

This keeps the container's published port reachable only from the VM itself.

Example run command:

```bash
sudo docker run -d \
  --name cyberlab-web \
  --restart unless-stopped \
  -p 127.0.0.1:8080:80 \
  -v ~/cyberlab-web:/usr/share/nginx/html:ro \
  nginx:alpine
```

The web directory is mounted read-only into the container.

## Host Nginx reverse proxy

A second Nginx instance runs directly on Ubuntu and acts as the public reverse proxy.

Traffic flow:

```text
Internet
   ↓
Host Nginx :80 / :443
   ↓
127.0.0.1:8080
   ↓
Docker Nginx container
```

This keeps the container private while giving the host a single controlled web entry point.

## Why use a reverse proxy?

Using a host reverse proxy provides a place to centralize:

- TLS termination
- HTTP-to-HTTPS redirects
- request logging
- security headers
- future rate limiting
- future routing to multiple containers

## Validation

Local checks:

```bash
curl http://127.0.0.1:8080
curl http://127.0.0.1
sudo ss -tulpn
```

External checks showed port 8080 remained filtered while ports 80 and 443 became reachable only after the required cloud and host firewall rules were added.
