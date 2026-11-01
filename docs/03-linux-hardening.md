# Linux Hardening

## Baseline inspection

Before making changes, the server was inspected with commands such as:

```bash
whoami
hostname
uname -a
ip addr
ip route
free -h
sudo ss -tulpn
```

This established the initial operating-system, network, memory, and listening-service baseline.

## SSH hardening

The VM was accessed with an Ed25519 SSH key rather than password authentication.

The final effective SSH settings are:

```text
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
```

A separate override file was used:

```text
/etc/ssh/sshd_config.d/99-cyberlab-hardening.conf
```

Before reloading SSH, configuration syntax was validated with:

```bash
sudo sshd -t
```

A second SSH session was opened before closing the first one to verify that remote access still worked.

## Reducing unnecessary services

Initial inspection found `rpcbind` listening on TCP and UDP port 111.

Because the server was not using NFS and had no NFS mounts in `/etc/fstab`, both the service and socket were disabled:

```bash
sudo systemctl disable --now rpcbind.socket
sudo systemctl disable --now rpcbind.service
```

Afterward, `ss -tulpn` confirmed that port 111 was no longer listening.

## Automatic security updates

Ubuntu's `unattended-upgrades` package was already installed and enabled.

The configuration included:

```text
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

This keeps security updates from depending entirely on manual patching.

## Fail2Ban

Fail2Ban was configured with a single SSH jail using the systemd journal backend.

Initial learning configuration:

```text
bantime = 10m
findtime = 10m
maxretry = 5
```

The configuration was validated before restart with:

```bash
sudo fail2ban-client -t
```

and verified with:

```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

## Hardening philosophy

The project follows a simple process:

```text
Discover → Understand → Change → Validate → Document
```

Services were not disabled merely because they looked unfamiliar. Their purpose and dependencies were checked first.
