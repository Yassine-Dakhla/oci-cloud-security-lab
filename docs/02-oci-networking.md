# OCI Networking

## VCN

The project uses a Virtual Cloud Network (VCN) with CIDR range:

```text
10.0.0.0/16
```

A VCN is the main private network boundary inside OCI.

## Subnets

Two regional subnets were created:

```text
Public subnet:  10.0.0.0/24
Private subnet: 10.0.1.0/24
```

The public subnet hosts `cyberlab-server`. The private subnet is reserved for future internal workloads.

## Internet connectivity

The VCN wizard created the supporting network components, including an Internet Gateway and route tables.

The public instance has:

- a private IPv4 address inside the VCN
- a public IPv4 address mapped by OCI

The public IP does not appear directly on the Linux interface. Linux sees the private VNIC address, while OCI performs the public mapping at the cloud networking layer.

## Default gateway

The VM learns its default gateway through DHCP. Traffic outside the local subnet is sent through the OCI virtual router and then routed according to the subnet route table.

## Security Lists

The public subnet uses a Security List as a cloud-level firewall.

During the project, ingress was intentionally expanded in stages:

```text
22/tcp  SSH
80/tcp  HTTP
443/tcp HTTPS
```

This was useful for demonstrating that opening a port in the Linux host firewall alone is not enough if OCI still blocks the traffic.

## Public vs private service exposure

The Docker application uses:

```text
127.0.0.1:8080
```

instead of `0.0.0.0:8080`.

That means the container is not directly exposed through the VCN. The host Nginx reverse proxy is the only public web entry point.
