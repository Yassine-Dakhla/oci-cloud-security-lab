# Firewall Security

## Two filtering layers

The project uses two separate network-control layers:

1. **OCI Security List** — controls traffic at the cloud subnet level.
2. **Ubuntu iptables** — controls traffic on the VM itself.

A service must be permitted by both layers before it becomes reachable from the internet.

## Important OCI Ubuntu finding

During the build, UFW was initially enabled and configured to allow SSH and HTTP. However, port 80 remained filtered externally.

Inspection showed that the OCI Ubuntu image already had an `iptables` policy similar to:

```text
ACCEPT established/related
ACCEPT ICMP
ACCEPT loopback
ACCEPT TCP/22
REJECT everything else
```

The catch-all `REJECT` occurred before UFW's chains, so UFW's allow rule for port 80 was never reached.

The project therefore switched away from UFW and used the OCI Ubuntu image's persistent `iptables` configuration directly.

## Persistent rules

The persistent rules are stored in:

```text
/etc/iptables/rules.v4
```

The intended public TCP rules are:

```text
22  SSH
80  HTTP
443 HTTPS
```

All three ACCEPT rules must appear before the final REJECT rule.

Example:

```text
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
```

Changes can be loaded with:

```bash
sudo iptables-restore < /etc/iptables/rules.v4
```

## External validation

Nmap was used from a separate machine to validate actual internet exposure.

Before opening HTTP:

```text
22/tcp   open
80/tcp   filtered
443/tcp  filtered
8080/tcp filtered
```

After opening the required OCI and host rules:

```text
22/tcp    open
80/tcp    open
443/tcp   open
8080/tcp  filtered
```

This demonstrated an important lesson: `ss` answers "what is listening locally?", while Nmap from another host answers "what can an external client actually reach?"
