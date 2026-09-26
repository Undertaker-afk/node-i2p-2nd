# Native TypeScript I2P Router — Implementation TODO

> This is a staged engineering checklist, not a claim that the router exists yet. A real router must interoperate with independent I2P routers; unit tests and a SAM facade alone are not sufficient.

The project will be implemented in TypeScript from scratch. It will not delegate protocol operation to the Java router. Protocol decisions must be checked against authoritative I2P specifications before code is considered complete.

## Project boundaries and protocol research

- [x] 001. Write a precise definition of router scope, supported transports, compatibility target, and non-goals.
- [ ] 002. Inventory authoritative I2P specifications and record source URLs and version dates.
- [ ] 003. Map each required protocol feature to its specification section before implementation.
- [ ] 004. Create a compatibility matrix for existing I2P router implementations and versions.
- [ ] 005. Define a policy for experimental features versus mandatory interoperability behavior.
- [ ] 006. Document protocol terms and distinguish router, tunnel, destination, and SAM concepts.
- [ ] 007. Identify cryptographic algorithms and parameters required by the chosen protocol version.
- [ ] 008. Record wire encodings, length limits, and canonical serialization requirements.
- [ ] 009. Create a decision log for protocol ambiguities and their resolutions.
- [ ] 010. Define how specification updates will be tracked and reviewed.
- [ ] 011. Identify legal and security review needs for cryptographic code.
- [ ] 012. Separate public protocol interfaces from internal implementation details.
- [ ] 013. Define a supported operating-system and Node.js version matrix.
- [ ] 014. Define memory, CPU, startup, and network resource budgets for a small router.
- [ ] 015. Write a threat model covering hostile peers, local applications, and compromised keys.
- [ ] 016. Define acceptable defaults for listen addresses and local administration.
- [ ] 017. List test fixtures that may be shared from other implementations and their licenses.
- [ ] 018. Plan a reproducible development environment without bundled router binaries.
- [ ] 019. Create a glossary for developers and maintainers.
- [ ] 020. Gate claims of router interoperability on measured integration tests.

## Architecture and core lifecycle

- [ ] 021. Define RouterConfig with validated bind, storage, logging, and resource settings.
- [ ] 022. Define explicit lifecycle states: stopped, starting, running, stopping, and failed.
- [ ] 023. Implement idempotent startup and shutdown transitions.
- [ ] 024. Ensure startup rollback closes components that already initialized after a later failure.
- [ ] 025. Ensure shutdown is bounded and reports components that fail to stop.
- [ ] 026. Add cancellation support for in-progress startup and tunnel creation.
- [ ] 027. Define typed interfaces for transports, netDb, tunnel manager, and local APIs.
- [ ] 028. Keep router orchestration independent from concrete network transport implementations.
- [ ] 029. Provide dependency injection for deterministic tests.
- [ ] 030. Add structured router health and readiness state.
- [ ] 031. Expose component state without leaking secret material.
- [ ] 032. Add graceful handling for uncaught shutdown signals.
- [ ] 033. Prevent duplicate router instances from opening the same state directory.
- [ ] 034. Add an explicit lock file with stale-lock recovery rules.
- [ ] 035. Define startup ordering and documented readiness prerequisites.
- [ ] 036. Define shutdown ordering so tunnels stop before transports and storage.
- [ ] 037. Add resource ownership conventions for sockets, timers, and file handles.
- [ ] 038. Add bounded queues and backpressure to every asynchronous subsystem.
- [ ] 039. Add runtime metrics interfaces without requiring a metrics server.
- [ ] 040. Add diagnostic reports suitable for support without private keys.

## Identity and key management

- [x] 041. Define router identity representation from the relevant I2P specification.
- [x] 042. Implement identity serialization and parsing with strict length checks.
- [ ] 043. Implement identity signature verification using approved cryptographic primitives.
- [ ] 044. Implement identity signing only after key formats are verified against reference vectors.
- [x] 045. Generate router keys from a cryptographically secure random source.
- [ ] 046. Persist private identity keys with restrictive file permissions.
- [x] 047. Write key files atomically and recover safely from interrupted writes.
- [ ] 048. Never log private keys, seeds, or sensitive derived material.
- [ ] 049. Define key rotation and identity migration behavior.
- [ ] 050. Add tests for malformed, truncated, and oversized identity encodings.
- [ ] 051. Add known-answer tests from authoritative public vectors.
- [ ] 052. Add deterministic test-key fixtures that cannot be selected in production.
- [ ] 053. Define encryption-key and signing-key separation rules.
- [ ] 054. Validate algorithm identifiers against the supported algorithm registry.
- [ ] 055. Reject unsupported identity algorithms explicitly.
- [ ] 056. Add zeroization strategy where runtime and cryptographic APIs permit it.
- [ ] 057. Document filesystem backup and restore requirements for router identity.
- [ ] 058. Prevent accidental identity regeneration when persisted files are corrupt.
- [ ] 059. Add secure permissions checks on Unix-like platforms.
- [ ] 060. Review key-handling code independently before network deployment.

## Cryptographic primitives and encodings

- [ ] 061. Create a cryptographic provider interface with narrow typed operations.
- [ ] 062. Prefer audited Node.js primitives or maintained packages over handwritten cryptography.
- [ ] 063. Verify each required primitive is available in supported Node.js versions.
- [ ] 064. Implement protocol-specific hash wrappers with explicit input framing.
- [ ] 065. Implement constant-time comparison for authentication-sensitive values.
- [ ] 066. Add randomness quality checks and fail closed if secure randomness is unavailable.
- [ ] 067. Implement key derivation only from precisely specified inputs and parameters.
- [ ] 068. Implement authenticated encryption wrappers with nonce and tag validation.
- [ ] 069. Implement signature wrappers with strict algorithm and encoding checks.
- [ ] 070. Add cross-implementation test vectors for every primitive wrapper.
- [ ] 071. Add negative vectors for invalid signatures and modified ciphertext.
- [ ] 072. Enforce maximum input lengths before expensive cryptographic operations.
- [ ] 073. Ensure errors do not disclose secret-dependent information.
- [ ] 074. Document the side-channel limitations of JavaScript runtimes.
- [ ] 075. Benchmark cryptographic hot paths under realistic load.
- [ ] 076. Add dependency review and vulnerability monitoring for any crypto package.
- [ ] 077. Keep protocol byte encoding separate from crypto operations.
- [ ] 078. Fuzz parsers before feeding decoded data into cryptographic functions.
- [ ] 079. Add compatibility tests across supported Node.js LTS versions.
- [ ] 080. Require independent review before declaring crypto implementation complete.

## Peer transports and connection management

- [ ] 081. Select initial transport based on verified current I2P protocol specifications.
- [ ] 082. Define a transport interface for dialing, listening, and authenticated peer streams.
- [ ] 083. Implement transport framing from exact protocol definitions.
- [ ] 084. Implement transport handshake and identity authentication.
- [ ] 085. Validate certificates, keys, and peer identities according to the specification.
- [ ] 086. Enforce handshake timeouts and byte limits.
- [ ] 087. Add peer connection states and explicit transitions.
- [ ] 088. Limit concurrent inbound and outbound connections.
- [ ] 089. Add per-peer and global rate limits.
- [ ] 090. Implement idle connection expiration and keepalive policy.
- [ ] 091. Handle half-closed connections and abrupt disconnects safely.
- [ ] 092. Add bounded write queues and honor socket backpressure.
- [ ] 093. Prevent duplicate peer connections from creating inconsistent state.
- [ ] 094. Implement reconnection backoff with jitter.
- [ ] 095. Add address parsing and reject unsafe or malformed peer endpoints.
- [ ] 096. Support IPv4 and IPv6 only where specifications and runtime permit.
- [ ] 097. Keep transport secrets out of logs and crash reports.
- [ ] 098. Add packet capture fixtures from permitted test environments.
- [ ] 099. Add interoperability tests with at least two independent routers.
- [ ] 100. Document firewall, NAT, and listening-port requirements.

## Router network database and reseeding

- [ ] 101. Define typed representations for router information and destination records.
- [ ] 102. Implement canonical record parsing and serialization from the specification.
- [ ] 103. Validate signatures before accepting records into the database.
- [ ] 104. Enforce record freshness and expiration rules.
- [ ] 105. Prevent replay and downgrade behaviors where the protocol defines protections.
- [ ] 106. Implement a bounded local store with atomic updates.
- [ ] 107. Index records by the correct protocol identifiers.
- [ ] 108. Add persistence migration and corruption recovery behavior.
- [ ] 109. Implement peer lookup and query response handling.
- [ ] 110. Add query deduplication and response timeouts.
- [ ] 111. Prevent database amplification through rate limiting and response limits.
- [ ] 112. Implement verified reseed source configuration.
- [ ] 113. Validate reseed responses and authenticated transport requirements.
- [ ] 114. Handle bootstrap failure without silently weakening trust checks.
- [ ] 115. Keep reseed credentials and private state out of logs.
- [ ] 116. Add seed-list update and rollback procedures.
- [ ] 117. Add tests with expired, invalid, duplicate, and malicious records.
- [ ] 118. Add database compaction and disk quota controls.
- [ ] 119. Expose aggregate database health metrics.
- [ ] 120. Test cold start, restart, and recovery with a realistic data set.

## Tunnel building and routing

- [ ] 121. Complete tunnel message/configuration models against the full supported protocol specification. (Partial: short-build, TunnelData/Gateway, tunnel-delivery, and fragment types exist.)
- [ ] 122. Complete build request encoding and strict parsing for all supported build formats. (Partial: ECIES short-build only.)
- [ ] 123. Complete response validation and failure classification. (Partial: authenticated short-build replies/statuses and timeout are handled.)
- [x] 124. Enforce tunnel hop-count and message-size bounds for the implemented short-build/data formats.
- [x] 125. Implement transit tunnel state, expiry, and cleanup for the implemented route types.
- [ ] 126. Verify tunnel participant behavior against independent routers; current behavior is only locally simulated.
- [ ] 127. Add bounded retries/cancellation to tunnel creation. (Current creator times out but does not retry.)
- [ ] 128. Complete peer selection from fresh, verified records. (Partial: a randomized path selector filters fresh ECIES RouterInfos with usable NTCP2 metadata.)
- [ ] 129. Add peer profile/suitability checks and automatically exclude recently failing peers. (Only caller-supplied exclusions exist.)
- [ ] 130. Complete tunnel-build resource limits. (Creator now bounds concurrent builds to a configurable 1..256 via `--max-concurrent-tunnel-builds`; global rate/CPU/memory quotas remain.)
- [ ] 131. Implement full teardown and cleanup after partial construction. (Partial: transient crypto and route state are cleaned on current failure paths.)
- [ ] 132. Complete forwarding backpressure and queue/resource controls. (Current sends await writes; no explicit bounded per-tunnel queue exists.)
- [ ] 133. Verify loop/duplicate handling against protocol rules. (A bounded replay cache exists; broader loop handling remains unverified.)
- [ ] 134. Add tunnel latency and failure metrics without peer-sensitive data.
- [ ] 135. Implement congestion-aware selection only if the specification supports it.
- [ ] 136. Complete tests for build success, rejection, timeout, and peer disconnect. (Success/rejection/timeout and simulated forwarding are covered; disconnect coverage remains.)
- [ ] 137. Fuzz tunnel message parsers and state transitions.
- [x] 138. Create a simulated multi-router tunnel topology with build and data-plane tests.
- [ ] 139. Validate tunnel behavior with reference routers and packet captures.
- [x] 140. Document the security properties and limitations of the experimental tunnel implementation.

## Garlic routing and message delivery

- [ ] 141. Model garlic messages and cloves using the canonical protocol structures.
- [ ] 142. Implement strict garlic message parser and serializer.
- [ ] 143. Implement authenticated encryption integration from verified protocol parameters.
- [ ] 144. Validate expiration and delivery instructions on every message.
- [ ] 145. Implement local delivery dispatch with bounded queues.
- [ ] 146. Implement tunnel delivery dispatch only after tunnels are interoperable.
- [ ] 147. Handle missing keys and expired messages without leaking sensitive details.
- [ ] 148. Limit nested message depth and aggregate decoded size.
- [ ] 149. Prevent parser recursion and resource exhaustion attacks.
- [ ] 150. Add replay handling where required by the protocol.
- [ ] 151. Implement delivery status handling and timeout semantics.
- [ ] 152. Add tests for malformed, nested, expired, and replayed messages.
- [ ] 153. Add fixtures interoperable with reference router implementations.
- [ ] 154. Ensure logs redact message payloads and destination secrets.
- [ ] 155. Measure memory behavior for maximum-size messages.
- [ ] 156. Add queue backpressure and overload rejection.
- [ ] 157. Document supported delivery instructions and unimplemented types.
- [ ] 158. Validate message handling under peer churn.
- [ ] 159. Add integration coverage for end-to-end destination delivery.
- [ ] 160. Review garlic routing security assumptions independently.

## Destinations, naming, and address books

- [ ] 161. Define destination key and address-book record formats from authoritative specs.
- [ ] 162. Implement hostname normalization with IDNA and protocol-specific constraints.
- [ ] 163. Implement local name lookup and explicit not-found behavior.
- [ ] 164. Implement address-book import with signature and format validation.
- [ ] 165. Prevent malicious hostname aliases and ambiguous normalization.
- [ ] 166. Add configurable trusted address-book sources.
- [ ] 167. Implement update policy with freshness and rollback protection.
- [ ] 168. Add local registration API only if its security model is defined.
- [ ] 169. Protect registration credentials and reject unauthorized updates.
- [ ] 170. Implement destination record storage with quotas.
- [ ] 171. Add duplicate and conflicting record handling.
- [ ] 172. Keep private destination keys separate from public address records.
- [ ] 173. Add tests for Unicode, punycode, case, trailing dot, and invalid labels.
- [ ] 174. Implement lookup caching with bounded TTL and invalidation.
- [ ] 175. Add privacy policy for outbound lookup requests.
- [ ] 176. Add user-facing diagnostics for untrusted or expired records.
- [ ] 177. Fuzz parsers and hostname normalization.
- [ ] 178. Test address-book compatibility with existing I2P tools.
- [ ] 179. Document how users import and validate address books.
- [ ] 180. Do not claim a hostname is authentic without verifying its provenance.

## SAM and local client APIs

- [ ] 181. Keep the existing SAM client API behavior covered while router APIs evolve.
- [x] 182. Implement a SAM server only after the router stream subsystem exists.
- [ ] 183. Negotiate supported SAM versions accurately.
- [ ] 184. Implement SAM session create, remove, and status semantics.
- [ ] 185. Implement stream connect and accept against actual router destinations.
- [ ] 186. Implement datagram APIs only if their protocol behavior is supported.
- [ ] 187. Validate all SAM commands and prevent command injection.
- [ ] 188. Enforce authentication or loopback-only access for local APIs.
- [ ] 189. Bound command line lengths and outstanding requests.
- [ ] 190. Handle client disconnects and session cleanup deterministically.
- [ ] 191. Add conformance tests against established SAM clients.
- [ ] 192. Add integration tests using standard I2P client applications.
- [ ] 193. Document supported SAM options and return codes.
- [ ] 194. Never imply SAM support means the router network stack is implemented.
- [ ] 195. Add protocol logging controls with payload redaction.
- [ ] 196. Add server-side resource quotas per session.
- [ ] 197. Implement graceful server shutdown and session teardown.
- [ ] 198. Fuzz command parsing and state handling.
- [ ] 199. Add API compatibility tests for documented examples.
- [ ] 200. Keep local API dependencies decoupled from core router lifecycle.

## HTTP proxy and user-facing tools

- [ ] 201. Maintain the existing HTTP proxy as a client of the SAM layer.
- [x] 202. Keep proxy bind default restricted to loopback.
- [x] 203. Validate absolute proxy URLs and reject clearnet targets.
- [ ] 204. Correctly preserve request methods, paths, headers, and streaming bodies.
- [ ] 205. Handle upstream error and timeout paths without leaking sockets.
- [ ] 206. Add limits for header sizes and concurrent proxy requests.
- [ ] 207. Reject unsupported URL schemes clearly.
- [ ] 208. Implement CONNECT tunneling only through real SAM streams.
- [ ] 209. Add proxy tests with fake SAM and local HTTP fixtures.
- [ ] 210. Add CLI validation for ports, hostnames, and storage paths.
- [ ] 211. Add version and diagnostic subcommands.
- [ ] 212. Add explicit warning before binding APIs beyond loopback.
- [ ] 213. Provide a router status command that does not expose secrets.
- [ ] 214. Add shell examples for curl and browser configuration.
- [ ] 215. Ensure command output is safe to copy into issue reports.
- [ ] 216. Add structured logging levels and JSON mode.
- [ ] 217. Add configuration file parsing with a documented schema.
- [ ] 218. Add config validation without starting network listeners.
- [ ] 219. Add environment variable precedence documentation.
- [ ] 220. Test installation and command behavior on clean Node.js environments.

## Persistence, configuration, and operations

- [ ] 221. Define stable configuration schema and defaults.
- [ ] 222. Reject unknown security-sensitive settings unless explicitly allowed.
- [ ] 223. Support environment overrides without logging secret values.
- [ ] 224. Implement atomic state file updates and crash recovery.
- [ ] 225. Protect state directory permissions and validate ownership where possible.
- [ ] 226. Implement disk quotas for caches and network database files.
- [ ] 227. Add backup and restore documentation for identity and state.
- [ ] 228. Implement safe schema migrations with rollback strategy.
- [ ] 229. Add storage corruption reporting and recovery mode.
- [ ] 230. Implement rotating logs with size and retention limits.
- [ ] 231. Add health status without exposing peer or destination identities unnecessarily.
- [ ] 232. Provide service-manager examples for common operating systems.
- [ ] 233. Add a container deployment guide that keeps secrets in mounted volumes.
- [ ] 234. Document required firewall openings and their defaults.
- [ ] 235. Add resource limit recommendations for low-memory systems.
- [ ] 236. Add graceful handling for read-only or full filesystems.
- [ ] 237. Add operational alerts for repeated tunnel and transport failures.
- [ ] 238. Add metrics export as an optional, separately secured feature.
- [ ] 239. Add a secure update and release verification process.
- [ ] 240. Test upgrade and rollback across supported versions.

## Security and abuse resistance

- [ ] 241. Publish a threat model before exposing any peer-facing listener.
- [ ] 242. Add parser size limits before allocating based on untrusted lengths.
- [ ] 243. Add connection, request, and cryptographic-work rate limits.
- [ ] 244. Prevent unbounded queues and memory growth under overload.
- [ ] 245. Use safe defaults for all network listener bindings.
- [ ] 246. Restrict local control interfaces to trusted users.
- [ ] 247. Review SSRF and clearnet escape paths in proxy and name lookup code.
- [ ] 248. Reject malformed encodings and ambiguous protocol values.
- [ ] 249. Add dependency and supply-chain auditing to CI.
- [ ] 250. Add static analysis and secret scanning to CI.
- [ ] 251. Create a vulnerability reporting policy and response process.
- [ ] 252. Review denial-of-service behavior under connection floods.
- [ ] 253. Review timing and error differences in authentication paths.
- [ ] 254. Review key lifecycle, backup, and file permission handling.
- [ ] 255. Review logging for metadata and destination privacy leakage.
- [ ] 256. Add fuzzing for every network-facing parser.
- [ ] 257. Add chaos tests for packet loss, latency, reordering, and disconnects.
- [ ] 258. Write security advisories for known missing protections.
- [ ] 259. Never enable insecure fallback behavior silently.
- [ ] 260. Require a security review before claiming production readiness.

## Testing and interoperability

- [ ] 261. Keep fast deterministic unit tests for each protocol parser.
- [ ] 262. Add known-answer tests for serialization and cryptographic primitives.
- [ ] 263. Add property tests for encode/decode round trips.
- [ ] 264. Fuzz all untrusted wire-format parsers continuously.
- [ ] 265. Build a mock transport for state-machine tests.
- [ ] 266. Build local multi-router test harnesses with isolated state directories.
- [ ] 267. Run tests against at least two existing I2P router implementations.
- [ ] 268. Add end-to-end destination lookup tests.
- [ ] 269. Add end-to-end tunnel creation and data transfer tests.
- [ ] 270. Add SAM conformance tests using an established client.
- [ ] 271. Add tests for restarts with persisted identity and database state.
- [ ] 272. Add network fault injection and peer churn scenarios.
- [ ] 273. Run tests across supported Node.js LTS versions.
- [ ] 274. Run tests on Linux, macOS, and Windows where feasible.
- [ ] 275. Keep live-network tests opt-in and never require public network access in unit CI.
- [ ] 276. Record reproducible test environment details for interoperability reports.
- [ ] 277. Add CI timeouts and cleanup to prevent leaked sockets.
- [ ] 278. Add coverage reporting for protocol and error branches.
- [ ] 279. Ensure tests do not use production private keys or user state.
- [ ] 280. Block release on failing unit, fuzz smoke, or interoperability gates.

## Performance and scalability

- [ ] 281. Benchmark startup and shutdown at realistic peer counts.
- [ ] 282. Benchmark message parsing and serialization under realistic payload sizes.
- [ ] 283. Measure heap and external-buffer usage during sustained operation.
- [ ] 284. Profile event loop delay during cryptographic and routing workloads.
- [ ] 285. Use worker threads only when measurement justifies their complexity.
- [ ] 286. Bound per-peer buffering and expose backpressure.
- [ ] 287. Bound tunnel count and concurrent tunnel construction.
- [ ] 288. Bound netDb cache size and disk usage.
- [ ] 289. Add load tests for connection churn and slow peers.
- [ ] 290. Add large-message and malformed-message stress tests.
- [ ] 291. Prevent expensive synchronous work on network event handlers.
- [ ] 292. Add adaptive overload rejection rather than unbounded queueing.
- [ ] 293. Measure latency distribution for lookup and stream establishment.
- [ ] 294. Profile garbage collection under long-running workloads.
- [ ] 295. Ensure timers and event listeners are cleaned up after failures.
- [ ] 296. Add resource budgets configurable for small devices.
- [ ] 297. Document expected throughput and limitations based on measurements.
- [ ] 298. Compare performance against reference router baselines where meaningful.
- [ ] 299. Keep performance tests isolated from correctness assertions.
- [ ] 300. Retest performance after changes to codecs and cryptographic paths.

## Documentation and release readiness

- [ ] 301. Write an accurate status page separating implemented, experimental, and missing parts.
- [ ] 302. Document architecture and trust boundaries.
- [ ] 303. Document configuration options and safe defaults.
- [ ] 304. Document first-start identity creation and backup.
- [ ] 305. Document how to connect a local application through SAM.
- [ ] 306. Document how to diagnose a failed router startup.
- [ ] 307. Document current incompatibilities with reference implementations.
- [ ] 308. Provide a threat model and security limitations.
- [ ] 309. Provide operator guidance for updates and backups.
- [ ] 310. Add API documentation for exported TypeScript interfaces.
- [ ] 311. Add protocol references adjacent to each implementation module.
- [ ] 312. Add contribution rules for security-sensitive code.
- [ ] 313. Add changelog entries for protocol and compatibility changes.
- [ ] 314. Automate reproducible builds and package integrity checks.
- [ ] 315. Verify generated package contains source maps and license notices as intended.
- [ ] 316. Run clean-install smoke tests before publishing.
- [ ] 317. Ensure package engines and runtime flags match actual support.
- [ ] 318. Never claim fully working until interoperability acceptance criteria pass.
- [ ] 319. Publish signed release artifacts and checksums.
- [ ] 320. Create a release checklist with security and interoperability sign-offs.

## Initial implementation milestones

- [x] 321. Add typed configuration and validation tests.
- [x] 322. Add a router lifecycle state machine with deterministic failure cleanup.
- [x] 323. Add dependency interfaces and mock implementations for tests.
- [ ] 324. Add secure state-directory initialization and locking.
- [ ] 325. Add transport abstraction without pretending it is a working transport.
- [ ] 326. Add protocol specification references and implementation status annotations.
- [x] 327. Add parser utilities only for formats that have verified specifications.
- [ ] 328. Add cryptographic provider interface and known-answer test harness.
- [ ] 329. Add structured diagnostic output for startup failures.
- [ ] 330. Add router core tests independent of a live network.
- [ ] 331. Add test fixtures and local transport harness.
- [ ] 332. Choose and document the first transport to implement.
- [ ] 333. Implement the selected transport handshake from specification.
- [ ] 334. Prove transport interoperability with a reference router.
- [ ] 335. Only then begin network database exchange implementation.
- [ ] 336. Only after peer exchange begin tunnel construction implementation.
- [ ] 337. Only after tunnels pass integration begin end-to-end message delivery.
- [ ] 338. Add SAM server integration after stream delivery works.
- [ ] 339. Run staged acceptance tests and publish results.
- [ ] 340. Reassess scope and schedule after each independently verified milestone.

## Current milestone

- [x] Establish the scope: native TypeScript router, not a wrapper.
- [x] Implement and test the typed router lifecycle and configuration foundation.
- [x] Implement standard and short I2NP header codecs plus incremental standard-frame decoding.
- [x] Generate and atomically persist an Ed25519/X25519 router identity.
- [x] Build/parse RouterInfo records and verify Ed25519 signatures.
- [x] Parse RouterInfo DatabaseStore messages with gzip and identity-hash checks.
- [x] Encode/decode unencrypted RouterInfo and exploratory DatabaseLookup messages.
- [x] Encode/decode DatabaseSearchReply messages.
- [x] Persist bounded RouterInfo records atomically and re-verify them on reload.
- [x] Implement outbound NTCP2 Noise XK SessionRequest, SessionCreated processing, and SessionConfirmed creation.
- [x] Implement NTCP2 SipHash length obfuscation and encrypted data-phase block framing.
- [x] Implement an outbound NTCP2 TCP connection routine and established connection wrapper.
- [x] Implement NTCP2 inbound responder/listener, bounded concurrent handshakes, replay detection, and bidirectional local socket tests.
- [ ] Verify NTCP2 initiator and responder against independent I2P routers.
- [x] Verify and import signed SU3 reseed ZIPs using pinned I2P reseed signer certificates.
- [x] Implement direct RouterInfo DatabaseLookup, DatabaseStore, and DatabaseSearchReply handling over NTCP2 peers.
- [ ] Add interoperability vectors and validate live reseed/network access against independent I2P routers.
- [ ] Implement routed netDb replies, tunnel building, and garlic routing.
- [x] Select NTCP2 as the first live transport milestone.
- [ ] Build interoperability harness before claiming network functionality.

**Checklist size:** 340 actionable tasks across 17 workstreams. Tasks remain unchecked until implemented and verified.

## Specification references consulted

- I2NP message structures, DatabaseStore, and version compatibility: https://geti2p.net/en/docs/specs/i2np/
- Common structures, RouterIdentity, RouterAddress, Mapping, and RouterInfo: https://geti2p.net/en/docs/specs/common-structures/
- Transport overview and current transport families: https://geti2p.net/en/docs/transport/
- NTCP2 specification: https://geti2p.net/en/docs/specs/ntcp2/
- Tunnel routing overview: https://geti2p.net/en/docs/how/tunnel-routing/
- ECIES-X25519 tunnel creation and short-build KDF/record rules: https://geti2p.net/spec/tunnel-creation-ecies
- ECIES-X25519 router Garlic messages, Noise N, and replay-protection DateTime block: https://i2p.net/en/docs/specs/ecies-routers/
- Smaller Tunnel Build Messages (Prop. 157), including inbound/outbound message flow and inbound Garlic requirement: https://i2p.net/en/proposals/157-new-tbm/
- Tunnel implementation roles and message processing: https://geti2p.net/en/docs/tunnels/implementation

As of 2026-09-26, the code includes an NTCP2 initiator and responder, a bounded TCP listener, bidirectional data-phase exchanges, a direct-peer RouterInfo lookup/store/search subset, and signed SU3 reseed verification/import. Experimental tunnel work includes ECIES short-build creation, a randomized selector for fresh verified ECIES RouterInfos with usable NTCP2 address metadata (plus explicit caller paths), transit forwarding, outbound-endpoint Garlic reply wrapping, AES tunnel-data processing, fragment reassembly, and a three-router simulated build/data path. The latest local verification passed all 80 tests, `npm run check`, `git diff --check`, and CLI help/configuration validation; the outbound creator also has a configurable concurrency cap. None of these tests establish independent-router interoperability. Normal `.i2p` application connectivity has not been demonstrated.

### Next implementation sequence

1. Add independent known-answer/interoperability vectors for NTCP2, ECIES short builds, reply records, tunnel layers, and Garlic; fix mismatches before building more features.
2. Implement inbound short-tunnel creation through a working outbound tunnel: add the specified ECIES Garlic wrapping/unwrapping so the raw STBM is delivered to (not exposed at) the IBGW, handle creator fake-record validation and reply routing, then test a complete simulated bidirectional route. Do not send a bare type-25 STBM to the IBGW.
3. Add managed inbound/outbound tunnel pools with bounded concurrency, refresh/retry policy, expiration cleanup, and peer-failure feedback.
4. Implement full Garlic session creation/ratcheting and routed netDb replies over those managed tunnels.
5. Add destination/name resolution and an I2CP or SAM server only after end-to-end tunnel delivery works.
6. Run interop against independent Java I2P and i2pd routers, then test `.i2p` application traffic; do not mark router readiness before this gate passes.
