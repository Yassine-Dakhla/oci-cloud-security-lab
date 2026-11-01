# Troubleshooting Notes

This file records problems encountered during the build and how they were diagnosed.

## Subnets appeared missing

### Symptom

The VCN existed, but the Subnets page showed no items.

### Cause

The OCI console compartment filter was set to the root compartment while the project resources were created inside the `cyberlab` compartment.

### Fix

Change the resource filter to the correct compartment.

### Lesson

OCI resources are compartment-scoped. When a resource appears to be missing, verify the active compartment filter first.

---

## UFW allowed HTTP but port 80 was still filtered

### Symptom

The server showed:

- Nginx active and listening on `0.0.0.0:80`
- UFW allowing TCP/80
- `curl http://127.0.0.1` returning HTTP 200

But an external Nmap scan still showed:

```text
80/tcp filtered
```

### Investigation

The OCI Security List was checked and TCP/80 was correctly allowed.

The next step was to inspect the host packet-filter rules:

```bash
sudo iptables -L INPUT -n -v --line-numbers
sudo iptables -S INPUT
```

The OCI Ubuntu image already contained a catch-all REJECT rule immediately after the SSH allow rule. The UFW chains were positioned after that REJECT, so traffic to port 80 never reached them.

### Fix

The project stopped relying on UFW and updated `/etc/iptables/rules.v4` directly, adding TCP/80 before the final REJECT rule. The rules were loaded with `iptables-restore`.

### Lesson

Firewall troubleshooting must follow the whole packet path. A rule shown as "allowed" by one firewall tool does not prove that an earlier rule or another layer is not dropping the traffic.

---

## Docker port intentionally remained filtered

### Observation

After the public website was working, Nmap showed TCP/8080 as filtered.

### Explanation

The container was intentionally published as:

```text
127.0.0.1:8080:80
```

rather than on every interface.

The public entry point is the host Nginx reverse proxy on ports 80/443.

### Lesson

A container does not need to expose its application port directly to the internet when a reverse proxy can provide the public interface.

---

## Safe remote-firewall workflow

When changing SSH or firewall configuration on a remote server:

1. Keep the existing SSH session open.
2. Validate syntax before reload where possible.
3. Apply the change.
4. Open a second SSH session.
5. Only close the original session after the second connection succeeds.

This reduces the chance of accidentally locking yourself out.
