# TypeScript I2P client (SAM v3)

A dependency-free Node.js HTTP proxy that connects to an existing I2P router through its SAM v3 bridge. This is an I2P **client**, not a router: it does not build tunnels itself. It requires Node.js 22.6+ (native TypeScript type stripping).

## Plan and architecture

1. Negotiate SAM 3.x with the router and create a transient STREAM session.
2. Resolve `.i2p` hostnames using SAM `NAMING LOOKUP`.
3. Open router-managed streams with SAM `STREAM CONNECT`.
4. Forward browser HTTP proxy requests and CONNECT tunnels over those streams.
5. Remove the transient session and close client sockets on shutdown.

The client restricts requests to HTTP `.i2p` destinations, validates hostnames and SAM command tokens, and binds the proxy to loopback by default. HTTPS `CONNECT` is passed through as a raw tunnel; no TLS is intercepted. No address-book subscription, router installation, or peer/tunnel implementation is included.

## Run

Install/run with Node.js 22.6 or later. Start an I2P router with its SAM bridge enabled (commonly `127.0.0.1:7656`), then:

```sh
npm start
```

Configure your browser's HTTP proxy as `127.0.0.1:4444`. Environment variables:

- `I2P_SAM_HOST`, `I2P_SAM_PORT` (defaults `127.0.0.1`, `7656`)
- `I2P_PROXY_HOST`, `I2P_PROXY_PORT` (defaults `127.0.0.1`, `4444`)

Example:

```sh
curl -x http://127.0.0.1:4444 http://i2p-project.i2p/hosts.txt
curl -x http://127.0.0.1:4444 http://reg.i2p/
```

`i2p-project.i2p/hosts.txt` is often used as a hosts-list location, while `reg.i2p` is a hostname-registration service. They are not built into the client, and reachability/content can change. This checkout's environment has no I2P router or SAM bridge, so I could not connect to either destination or verify current pages. To query them, run the examples locally with a router and SAM bridge enabled. Do not expose the local proxy to an untrusted network.

## Native TypeScript router (experimental)

The native router implementation is tracked in [`TODO.md`](./TODO.md). It has persistent Ed25519/X25519 router identities, signed RouterInfo records, a bounded verified netDb, a bounded NTCP2 inbound listener and outbound connector, authenticated bidirectional I2NP data sessions, direct RouterInfo DatabaseLookup/Store/SearchReply handling, signed SU3 reseed verification, peer bootstrap, and experimental ECIES short-build transit plus AES tunnel-data forwarding and fragment codecs. Local tests exercise native nodes and tunnel components. The reseed network calls could not be reached from this environment, and the transport and tunnel handling have not yet been tested against an independent Java I2P or i2pd router.

To run the experimental peer/transit node, supply an externally reachable address and open the published TCP port:

```sh
npm run router -- --public-host YOUR_REACHABLE_IP --port 12345
```

The process stores its identity and netDb under `~/.i2p-native-ts` by default. Use `--state-dir` to change that location; `--bind-host` controls the local bind address. Transit builds are accepted by default up to 5,000 active tunnels; set `--max-transit-tunnels` to adjust the bound or `--no-transit` to decline new builds. Outbound short-tunnel creation is capped at eight concurrent builds by default; `--max-concurrent-tunnel-builds` sets a limit from 1 to 256. On first startup it attempts to bootstrap from pinned-certificate HTTPS SU3 reseed servers. It requires a routable address, firewall/NAT configuration, and outbound HTTPS access. The tunnel code remains experimental and incomplete. It now has a short-build outbound creator that can randomly select a path from fresh, verified ECIES RouterInfos with NTCP2 address metadata, or accept a caller-supplied path; building still requires an already-existing inbound reply tunnel. Selection has no peer-history or performance scoring. The code also has a tested outbound-endpoint Garlic return path and transit/data handling. It does not build inbound tunnels, maintain inbound/outbound tunnel pools, implement general garlic-session routing, publish floodfill records, manage destinations, or provide SAM/I2CP application access. The route tests use simulated peers; no independent-router interoperability or normal-network tunnel use has been demonstrated. It is not a general-purpose I2P router, and applications cannot yet use it to reach `.i2p` destinations.

The pinned reseed public certificates are based on the i2pd project trust-anchor set documented in `src/router/netdb/reseed-certs/README.md`. Legacy RouterInfo signature types fail closed. Independent-router interoperability and real-network reseed access remain required before treating the native router as network-ready.

## Tests

```sh
npm test
npm run check
```

Tests include SAM client coverage; I2NP and netDb parsing; identity persistence; signed SU3 bundle verification; native two-node NTCP2 handshakes, bidirectional I2NP exchanges, and direct netDb lookups; tunnel-build crypto and creator, multi-hop simulated transit routing, OBEP Garlic reply wrapping, fixed-size tunnel data, fragment framing/reassembly; plus config and lifecycle checks. These are local conformance/regression tests, not independent-router interoperability or live I2P end-to-end tests.
