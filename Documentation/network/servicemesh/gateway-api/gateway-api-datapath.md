# Cilium Gateway API datapath walkthrough (default vs host-network)

This document consolidates the Gateway API behavior and focuses on how the external load balancer is created, how traffic reaches Envoy, and why certain data path choices are required.

---

## 1) Load balancer creation: default vs host-network

### Default (non-host-network) mode
The Gateway API controller (Cilium Operator) creates a Kubernetes **Service** for each Gateway. The Service **defaults to type `LoadBalancer`** unless host-network mode is enabled.

```go
// If hostNetwork is enabled, it returns ServiceTypeClusterIP. The default value is ServiceTypeLoadBalancer.
func (t *gatewayAPITranslator) toServiceType(params *model.Service) corev1.ServiceType {
	if t.cfg.HostNetworkConfig.Enabled {
		return corev1.ServiceTypeClusterIP
	}
	if params == nil {
		return corev1.ServiceTypeLoadBalancer
	}
	return corev1.ServiceType(params.Type)
}
```

Because the Service is type `LoadBalancer`, the **cloud provider’s load balancer controller/CCM** is expected to provision the external LB for that Service.

### Host-network mode
Host-network mode **disables the LoadBalancer Service mode** and **binds listeners directly on node interfaces**. As the docs indicate these are mutually exclusive:

```rst
* Enabling the Cilium Gateway API host network mode automatically disables the LoadBalancer type Service mode. They are mutually exclusive.
* The listener is exposed on all interfaces (0.0.0.0 for IPv4 and/or :: for IPv6).
```

So in host-network mode:
- The Service type is **ClusterIP** (per the translator logic above).
- There is **no Service-based external LB** created; external routing/LB must be provisioned outside the Service model.

---

## 2) Default (non-host-network) datapath

### Diagram
```
External Client
   |
   v
[External LB]
   |
   v
Node IP + Service Port
   |
   v
[eBPF intercepts Service traffic]
   |
   v
TPROXY redirect --> Local Envoy (per-node)
   |
   v
Envoy opens upstream connection to backend Pod with the node's Ingress IP
   |
   v
Backend replies to Envoy -> Envoy replies to Client
```

### Key behavior
The ingress reference describes how traffic reaches Envoy when exposed via LoadBalancer or NodePort:

```rst
Cilium's Ingress and Gateway API config is exposed with a Loadbalancer or NodePort
service, or optionally can be exposed on the Host network also. But in all of
these cases, when traffic arrives at the Service's port, eBPF code intercepts
the traffic and transparently forwards it to Envoy (using the TPROXY kernel facility).
```

Docs also clearly indicate that the **source IP is preserved** when traffic is forwarded to Envoy:

```rst
In *both* externalTrafficPolicy cases, traffic will arrive at any node
in the cluster, and be forwarded to Envoy while keeping the source IP intact.
```

---

## 3) Host-network mode datapath

### Diagram
```
External Client
   |
   v
(External LB / routing outside K8s Service model)
   |
   v
Node IP : Gateway Port (host listener)
   |
   v
Envoy listener bound to 0.0.0.0/::
   |
   v
Envoy -> Backend Pod (with node's ingress IP)
   |
   v
Backend -> Envoy -> Client
```

### Listener binding in host-network mode
Host-network mode explicitly binds Envoy listeners to **all interfaces**:

```go
if i.Config.HostNetworkConfig.Enabled {
	res = append(res, withHostNetworkPort(m, i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled))
}
```

```go
bindAddresses := []string{}
if ipv4Enabled {
	bindAddresses = append(bindAddresses, "0.0.0.0")
}
if ipv6Enabled {
	bindAddresses = append(bindAddresses, "::")
}
```

---

## 4) Why a dedicated IP is required for Envoy/Gateway

### Delegated IPAM support for Envoy/Gateway
When delegated IPAM is enabled, the agent now invokes the delegated IPAM plugin
using the CNI config to allocate per-node ingress IPs for Envoy/Gateway. This
keeps the ingress identity enforcement model intact while allowing delegated IPAM.

```go
netConf, rawConfig, err := d.cniConfigManager.GetCiliumNetConf()
ipamRawResult, err := cniInvoke.ExecPluginWithResult(d.ctx, pluginPath, rawConfig, args, exec)
```

### The routing-table reason (not just “marks”)
Proxy routing uses **policy routing** and installs **local/next-hop routes** anchored on the **Cilium internal IP**. Marks select the table, but the table still needs a concrete IP target which is the Cilium_host IP:

```go
fromProxyToCiliumHostRoute4 := route.Route{
	Table: linux_defaults.RouteTableFromProxy,
	Prefix: net.IPNet{
		IP:   ipv4,
		Mask: net.CIDRMask(32, 32),
	},
	Device: device,
	Type:   route.RTN_LOCAL,
}

fromProxyDefaultRoute4 := route.Route{
	Table:   linux_defaults.RouteTableFromProxy,
	Nexthop: &ipv4,
	Device:  device,
}
```
---

## 5) Why backend pods don’t reply directly to the external client

For proxied HTTP/HTTPS, Envoy **terminates the client connection** and opens a **new upstream TCP connection** to the backend with Node's Ingress IP. This is why the backend’s TCP peer is the node from which Envoy originated the backend connection, and replies go back to Envoy rather than directly to the client. 

---

## 6) Network policy enforcement and the `ingress` identity

When traffic arrives at Envoy for Ingress or Gateway API, it is assigned the special **`ingress` identity** in Cilium’s policy engine. This is separate from the node IP identity and is described as an additional policy enforcement step:

Doc ref:

```rst
However, for ingress config, there's also an additional step. Traffic that arrives at
Envoy *for Ingress or Gateway API* is assigned the special ``ingress`` identity
in Cilium's Policy engine.
```

There are **two logical policy enforcement points** for ingress traffic:

```rst
Traffic coming from outside the cluster is usually assigned the ``world`` identity
(unless there are IP CIDR policies in the cluster). This means that there are
actually *two* logical Policy enforcement points in Cilium Ingress - before traffic
arrives at the ``ingress`` identity, and after, when it is about to exit the
per-node Envoy.
```

**Implication for the question raised:** even if Envoy’s upstream connection uses the node IP at L3, the policy enforcement for Gateway API relies on the **`ingress` identity** assigned when traffic reaches Envoy. The enforcement point is based on this special identity (and the policy engine integration with Envoy), not strictly on the node IP identity.

---

## 7) Reserved `ingress` identity, ingress IPs, and why they must be unique per node

This section consolidates the identity/IP flow that underpins Gateway/Ingress policy enforcement and why it requires per-node ingress IPs—even in host-network mode.

### 7.1) Who gets `reserved:ingress` and how it is wired

The agent creates a **special ingress endpoint** that:
- Has **no veth**, **no BPF datapath**, and is marked as **host-namespace reachable**.
- Uses **the node’s ingress IPs** as its endpoint IPs.
- Is the only endpoint initialized with **`reserved:ingress`**, keeping it distinct from normal node IP identities.

```go
// Ingress endpoint is reachable via the host networking namespace
// Host delivery flag is set in lxcmap
ep.properties[PropertyAtHostNS] = true

// Ingress endpoint has no bpf policy maps
ep.properties[PropertySkipBPFPolicy] = true

// Ingress endpoint has no bpf programs
ep.properties[PropertyWithouteBPFDatapath] = true

ep.IPv4, _ = netipx.FromStdIP(node.GetIngressIPv4(logger))
ep.IPv6, _ = netip.AddrFromSlice(node.GetIngressIPv6(logger))
```

This ingress endpoint is then initialized with **`reserved:ingress`**, which is the identity used by policy enforcement for Gateway/Ingress traffic:

```go
// InitWithIngressLabels initializes the endpoint with reserved:ingress.
func (e *Endpoint) InitWithIngressLabels(ctx context.Context, launchTime time.Duration) {
	if !e.isIngress {
		return
	}
	epLabels := labels.Labels{}
	epLabels.MergeLabels(labels.LabelIngress)
	...
	e.UpdateLabels(..., epLabels, epLabels, true)
}
```

**Result:** the `reserved:ingress` identity is tied to this **special ingress endpoint**, not to the node IP identity. This is how Cilium can enforce policy at the Envoy boundary even when Envoy’s upstream TCP connections use the node ingress IP at L3.

---

### 7.2) Where ingress IPs come from (and how they’re annotated)

Ingress IPs are tracked on the node as dedicated fields:

```go
// IPv4IngressIP if not nil, this is the IPv4 address of the
// Ingress listener on the node.
IPv4IngressIP net.IP
// IPv6IngressIP if not nil, this is the IPv6 address of the
// Ingress listener located on the node.
IPv6IngressIP net.IP
```

They are also stored in **Kubernetes Node annotations**, separate from `cilium_host` IP annotations:

```go
// V4IngressName / V6IngressName store the Ingress listener IPs on the Node.
V4IngressName      = "network.cilium.io/ipv4-Ingress-ip"
V6IngressName      = "network.cilium.io/ipv6-Ingress-ip"

// CiliumHostIP / CiliumHostIPv6 store cilium_host interface IPs.
CiliumHostIP       = "network.cilium.io/ipv4-cilium-host"
CiliumHostIPv6     = "network.cilium.io/ipv6-cilium-host"
```

These ingress IPs are read from Node annotations and stored in the node model:

```go
if ingressIP, ok := annotation.Get(k8sNode, annotation.V4IngressName, ...); ok && ingressIP != "" {
	newNode.IPv4IngressIP = net.ParseIP(ingressIP)
}
```

**Key distinction:** ingress IPs are **not** the same as `cilium_host` IPs. They are dedicated ingress listener addresses used by the ingress endpoint and `reserved:ingress` identity.

---

### 7.3) Why ingress IPs must be unique per node (even in host-network mode)

Each node’s ingress IPs are injected into **IPCache** with:
- **`labels.LabelIngress`** (reserved:ingress identity), and
- a **TunnelPeer** that points to that node’s IP.

```go
m.ipcache.UpsertMetadata(prefixCluster, n.Source, resource,
	labels.LabelIngress,
	ipcacheTypes.TunnelPeer{Addr: nodeIP},
	m.endpointEncryptionKey(&n))
```

This creates a **prefix → node association** in IPCache. If you reuse the **same ingress IP on multiple nodes**, these IPCache entries will **conflict**, because the same prefix would be associated with multiple TunnelPeers. The last writer wins, leading to unstable or incorrect identity/metadata bindings.

**Therefore:** ingress IPs must be **unique per node** to preserve a stable, unambiguous prefix→node association for `reserved:ingress`.

---

### 7.4) Why this still applies in host-network mode

Host-network mode only changes **listener binding** and **Service type**. It does **not** remove the ingress endpoint or the need for `reserved:ingress` identity and IPCache metadata. The ingress endpoint still needs its ingress IPs to exist because:
- the **endpoint IPs** are set to `node.GetIngressIPv4/IPv6`, and
- the **ingress identity** is tied to that endpoint, regardless of how listeners are bound.

So, even in host-network mode:
- `reserved:ingress` identity still exists,
- ingress IPs are still required,
- and those ingress IPs still must be **unique per node**.

---

## 8) Envoy bpf_metadata: how ingress IPs are used

The Envoy listener filter `cilium.bpf_metadata` explicitly carries ingress settings, and it uses the **configured ingress IPs** for **north/south L7 LB** to derive the source identity and policy lookup.

The filter configuration exposes ingress vs egress and the per-family source addresses:

```proto
// 'true' if the filter is on ingress listener, 'false' for egress listener.
bool is_ingress = 2;

// True if the listener is used for an L7 LB.
bool is_l7lb = 4;

// Source address to be used whenever the original source address is not used.
string ipv4_source_address = 5;
string ipv6_source_address = 6;
```

Inside the filter, for **north/south L7 LB** (which is how Ingress/Gateway traffic is handled), the filter:
- selects the **local ingress IP** matching the IP family of the connection,
- resolves the **source identity** for that ingress IP, and
- disables original-source usage for the upstream connection.

```cpp
// Use the configured IPv4/IPv6 Ingress IPs as starting point for the sources addresses
IpAddressPair source_addresses(ipv4_source_address_, ipv6_source_address_);

// North/south L7 LB: pick local ingress source address and use it for policy identity
const Network::Address::Ip* ingress_ip = selectIpVersion(sip->version(), source_addresses);
...
source_identity = resolvePolicyId(ingress_ip);
...
// Original source address is never used for north/south LB
src_address = nullptr;
```

This is the concrete, Envoy-side mechanism that makes the **ingress IPs** (and their `reserved:ingress` identity mapping) meaningful for Gateway/Ingress traffic, beyond simply “arriving at an ingress listener.”

---

## 9) Pros/cons and limitations

### Default (non-host-network) mode
**Pros**
- Automatic **external LB creation** via Service type `LoadBalancer`.
- Standard Kubernetes workflow for managed clouds.
- eBPF+TPROXY delivery to Envoy with **source IP preserved** to Envoy.

**Limitations / considerations**
- Requires a cluster environment that **supports `LoadBalancer` Services**.

### Host-network mode
**Pros**
- Useful when **LoadBalancer Services are unavailable** or when external LB/routing is managed outside K8s.
- Envoy binds directly to host interfaces (`0.0.0.0` / `::`). While this can be a security concern, it would be useful in dev environments.

**Limitations / considerations** 
- **No Service-based external LB** is created (Service type is ClusterIP).
- Ports must be **unique across nodes** (port conflicts are possible).
- Binding to **privileged ports** requires extra capabilities (`NET_BIND_SERVICE`).

---

## 10) Recommended mode for typical managed K8s (e.g., AKS)

AKS environment supports **LoadBalancer Services**, the default mode is the more natural fit:
- Cilium creates a `LoadBalancer` Service per Gateway.
- The cloud provider’s LB controller provisions the external load balancer.

Host-network mode is intended for environments where **`LoadBalancer` Services are unavailable** or when external LB/routing is managed outside the Kubernetes Service model and more importantly would still need a node unique ingress IP.

Cilium also provides a node selector mechanims that allows us to tag a subset of nodes as dedicated gateway nodes rather than all the nodes in the cluster.

---

## 11) End-to-end summary (side-by-side)

| Aspect | Default (non-host-network) | Host-network |
|---|---|---|
| Service type | LoadBalancer | ClusterIP |
| External LB | Created by cloud LB controller from Service | Not created by Service; must be external |
| Listener binding | Not explicitly bound to 0.0.0.0/:: in translator | Explicitly bound to 0.0.0.0/:: |
| Traffic delivery | LB → Service port → eBPF+TPROXY → Envoy | External routing → Node IP/Port → Envoy |
| Dedicated IP requirement | Required (routing table next-hop/local route) | Still required (same routing table requirement) |

---

## 12) Source references

### Gateway Service type selection
```go
// If hostNetwork is enabled, it returns ServiceTypeClusterIP. The default value is ServiceTypeLoadBalancer.
func (t *gatewayAPITranslator) toServiceType(params *model.Service) corev1.ServiceType {
	if t.cfg.HostNetworkConfig.Enabled {
		return corev1.ServiceTypeClusterIP
	}
	if params == nil {
		return corev1.ServiceTypeLoadBalancer
	}
	return corev1.ServiceType(params.Type)
}
```

### Host-network mode doc
```rst
* Enabling the Cilium Gateway API host network mode automatically disables the LoadBalancer type Service mode. They are mutually exclusive.
* The listener is exposed on all interfaces (0.0.0.0 for IPv4 and/or :: for IPv6).
```

### Listener binding (host-network)
```go
if i.Config.HostNetworkConfig.Enabled {
	res = append(res, withHostNetworkPort(m, i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled))
}
```

```go
bindAddresses := []string{}
if ipv4Enabled {
	bindAddresses = append(bindAddresses, "0.0.0.0")
}
if ipv6Enabled {
	bindAddresses = append(bindAddresses, "::")
}
```

### TPROXY and Envoy forwarding
```rst
Cilium's Ingress and Gateway API config is exposed with a Loadbalancer or NodePort
service, or optionally can be exposed on the Host network also. But in all of
these cases, when traffic arrives at the Service's port, eBPF code intercepts
the traffic and transparently forwards it to Envoy (using the TPROXY kernel facility).
```

### Source IP preserved when forwarded to Envoy
```rst
In *both* externalTrafficPolicy cases, traffic will arrive at any node
in the cluster, and be forwarded to Envoy while keeping the source IP intact.
```

### Policy enforcement and the `ingress` identity
```rst
However, for ingress config, there's also an additional step. Traffic that arrives at
Envoy *for Ingress or Gateway API* is assigned the special ``ingress`` identity
in Cilium's Policy engine.
```

```rst
Traffic coming from outside the cluster is usually assigned the ``world`` identity
(unless there are IP CIDR policies in the cluster). This means that there are
actually *two* logical Policy enforcement points in Cilium Ingress - before traffic
arrives at the ``ingress`` identity, and after, when it is about to exit the
per-node Envoy.
```

### Delegated IPAM and dedicated ingress IPs
When delegated IPAM is enabled, the agent allocates the ingress IPs via the
delegated IPAM plugin instead of the built-in IPAM allocator. This preserves the
dedicated ingress IP model required for Envoy/Gateway identity enforcement.

### Proxy routing: local route + next-hop to Cilium internal IP
```go
fromProxyToCiliumHostRoute4 := route.Route{
	Table: linux_defaults.RouteTableFromProxy,
	Prefix: net.IPNet{
		IP:   ipv4,
		Mask: net.CIDRMask(32, 32),
	},
	Device: device,
	Type:   route.RTN_LOCAL,
}

fromProxyDefaultRoute4 := route.Route{
	Table:   linux_defaults.RouteTableFromProxy,
	Nexthop: &ipv4,
	Device:  device,
}
```

### TLS passthrough (backend sees Envoy as source)
```rst
Because it's a new TCP stream, as far as the backends are concerned,
the source IP is Envoy (which is often the Node IP, depending on your Cilium config).
```
