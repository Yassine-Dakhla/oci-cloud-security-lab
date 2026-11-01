# Docker Web Container

The web application container is intentionally bound only to localhost.

Example:

```bash
sudo docker run -d \
  --name cyberlab-web \
  --restart unless-stopped \
  -p 127.0.0.1:8080:80 \
  -v ~/cyberlab-web:/usr/share/nginx/html:ro \
  nginx:alpine
```

## Why localhost?

Publishing to `127.0.0.1:8080` prevents clients on the internet from connecting directly to the container port.

Public web traffic instead follows:

```text
Internet → host Nginx :443 → 127.0.0.1:8080 → Docker container
```

## Verification

On the server:

```bash
sudo docker ps
curl http://127.0.0.1:8080
sudo ss -tulpn | grep 8080
```

The listening address should be `127.0.0.1:8080`, not `0.0.0.0:8080`.

From an external machine, TCP/8080 should not be publicly reachable.
