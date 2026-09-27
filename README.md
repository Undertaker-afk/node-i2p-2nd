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

The native router implementation is tracked in [`TODO.md`](./TODO.md). It has persistent Ed25519/X25519 router identities, signed RouterInfo records, a bounded verified netDb, NTCP2 (TCP) and SSU2 (UDP) transports with inbound listeners and outbound dialers, authenticated bidirectional I2NP data sessions, direct RouterInfo DatabaseLookup/Store/SearchReply handling, signed SU3 reseed verification, peer bootstrap, and experimental ECIES short-build transit plus AES tunnel-data forwarding and fragment codecs. Local tests exercise native nodes and tunnel components. The reseed network calls could not be reached from this environment, and the transport and tunnel handling have not yet been tested against an independent Java I2P or i2pd router.

To run the router, supply an externally reachable address and open **both** transports on your firewall/NAT:

```sh
npm run netcheck                     # optional: checks reseed HTTPS, UDP egress (STUN), TCP interception, local binds
npm run router -- --public-host YOUR_REACHABLE_IP --port 12345
curl -x http://127.0.0.1:4444 http://notbob.i2p/hosts.txt
```

The local RouterInfo publishes two addresses for the same host:

| Transport | Protocol | Port | Published options |
| --- | --- | --- | --- |
| NTCP2 | TCP | `--port` (default 12345) | `host`, `port`, `s`, `i` (AES IV), `v=2` |
| SSU2 | UDP | `--ssu-port` (default: **same number** as `--port`) | `host`, `port`, `s` (router X25519 key), `i` (32-byte intro key, persisted in `<state-dir>/ssu2.intro`), `v=2`, `caps=4` |

So by default you must allow inbound **TCP 12345 and UDP 12345**. `--no-ssu2` publishes NTCP2 only. Outbound, the router dials SSU2 first when a peer publishes it and falls back to NTCP2; SSU2-only routers are valid tunnel hops. Other router flags: `--peers <n>` direct peers to bootstrap (default 16), `--reseed-file <i2pseeds.su3>` for networks where the HTTPS reseeds are blocked, `--sam-port`/`--no-sam`. All client APIs stay on loopback: HTTP proxy `:4444` (addresshelper and optional `--outproxy`), SOCKS `:4447`, SAM `:7656`, I2CP `:7654`, I2PControl `:7650`, console `:7070`.

The process stores its identity and netDb under `~/.i2p-native-ts` by default (`--state-dir` changes it; `--bind-host` sets the transport bind address, default `0.0.0.0`). After bootstrap it builds 1-hop exploratory tunnels first (used for netDb lookups), then 2-hop client tunnels. It tests tunnel pairs with I2NP DeliveryStatus, scores peers for hop selection, and only picks hops that accept short tunnel builds (router ≥ 0.9.51, no `G` cap). LeaseSet lookups go to the floodfills closest to the daily routing key `SHA256(key || yyyyMMdd)`. Transit builds are accepted by default, up to 5,000 active tunnels. `[diag]` log lines report dial failures per peer/transport, built tunnels and their hops, tunnel test results, LeaseSet lookups (floodfill, outbound gateway, reply tunnel), DatabaseSearchReply peers, SSU2 handshake errors, and a status line every minute.

### SSU2

`src/router/transport/ssu2/` implements SSU2 over `node:dgram`: TokenRequest/Retry, the Noise XK handshake (`Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256`) as SessionRequest/SessionCreated/SessionConfirmed with the RouterInfo in SessionConfirmed (fragmented if needed), ChaCha20 header protection, and a Data phase. The Data phase covers packet numbers, ACK blocks with ranges, retransmission, I2NP blocks with fragmentation and reassembly, NewToken, DateTime/Address blocks, termination, and keepalive. Peer Test, Relay/introducers, connection migration, and PQ variants are not implemented, so a firewalled router cannot be reached over SSU2.

### Private SSU2 mini-network (end-to-end without internet)

```sh
npm run mininet            # exits 0 when the request below returns 200
npm run mininet -- --keep  # leave it running, then: curl -x http://127.0.0.1:14444 http://notbob.i2p/hosts.txt
```

This starts 10 SSU2-only routers (2 floodfills; none publishes NTCP2) plus two real `router-cli.ts` processes. Router B serves a local HTTP server through a tunnels.conf server tunnel. Router A's `hosts.txt` maps `notbob.i2p` to B's destination. Every step is the real code path: A's proxy does a LeaseSet lookup at a floodfill through exploratory tunnels with an encrypted reply, then an ECIES destination handshake and streaming over A's outbound and B's inbound 2-hop tunnels. Every router-to-router hop is SSU2.

The pinned reseed public certificates are based on the i2pd project trust-anchor set documented in `src/router/netdb/reseed-certs/README.md`. Legacy RouterInfo signature types fail closed. Interoperability with independent routers (Java I2P, i2pd) and real-network reseed access still have to be shown before treating the native router as network-ready. In the development sandbox, outbound HTTPS to the reseeds is reset after ClientHello, outbound UDP gets no replies, and outbound TCP is terminated by a transparent proxy (`npm run netcheck` shows all three). So the live `notbob.i2p` request has only been run on the private mini-network above.

## Tests

```sh
npm test
npm run check
```

Tests include SAM client coverage; I2NP and netDb parsing; identity persistence; signed SU3 bundle verification; native two-node NTCP2 handshakes, bidirectional I2NP exchanges, and direct netDb lookups; SSU2 TokenRequest/Retry, loopback UDP handshakes, I2NP ping over SSU2 data, and a node test that dials SSU2-only peers and builds 2-hop tunnels through them; HTTP proxy fetches over a destination stream; parallel streams to one destination; tunnel-build crypto and creator, multi-hop simulated transit routing, OBEP Garlic reply wrapping, fixed-size tunnel data, fragment framing/reassembly; plus config and lifecycle checks. These are local conformance/regression tests, not independent-router interoperability or live I2P end-to-end tests.
