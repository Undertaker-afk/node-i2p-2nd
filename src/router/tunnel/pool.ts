import { EventEmitter } from 'node:events';
import { randomInt } from 'node:crypto';
import type { RouterIdentityKeys } from '../identity.ts';
import type { BuiltInboundTunnel, BuiltOutboundTunnel, ShortBuildHop } from './builder.ts';
import type { ShortTunnelBuildCreator } from './builder.ts';
import type { TransitTunnelService } from './transit.ts';
import { wrapEciesRouterGarlicMessage } from './garlic.ts';
import type { I2npMessage } from '../protocol/i2np.ts';

export type TunnelPoolOptions = {
  identity: RouterIdentityKeys;
  builder: ShortTunnelBuildCreator;
  transit: TransitTunnelService;
  selectPath: (hopCount: number, excluded: readonly Buffer[]) => ShortBuildHop[];
  sendThroughOutbound: (tunnel: BuiltOutboundTunnel, message: I2npMessage, delivery: { type: 'router'; identityHash: Buffer }) => Promise<void>;
  inboundCount?: number;
  outboundCount?: number;
  hopCount?: number;
  maintainIntervalMs?: number;
};

/** Maintains inbound and outbound client tunnels, bootstrapping from a 0-hop inbound reply path. */
export class TunnelPool extends EventEmitter {
  readonly inbound: BuiltInboundTunnel[] = [];
  readonly outbound: BuiltOutboundTunnel[] = [];
  private zeroHopInboundId: number | undefined;
  private readonly identity: RouterIdentityKeys;
  private readonly builder: ShortTunnelBuildCreator;
  private readonly transit: TransitTunnelService;
  private readonly selectPath: TunnelPoolOptions['selectPath'];
  private readonly sendThroughOutbound: TunnelPoolOptions['sendThroughOutbound'];
  private readonly inboundCount: number;
  private readonly outboundCount: number;
  private readonly hopCount: number;
  private readonly maintainIntervalMs: number;
  private maintaining = false;
  private timer: NodeJS.Timeout | undefined;

  constructor(options: TunnelPoolOptions) {
    super();
    this.identity = options.identity;
    this.builder = options.builder;
    this.transit = options.transit;
    this.selectPath = options.selectPath;
    this.sendThroughOutbound = options.sendThroughOutbound;
    this.inboundCount = options.inboundCount ?? 2;
    this.outboundCount = options.outboundCount ?? 2;
    this.hopCount = options.hopCount ?? 2;
    this.maintainIntervalMs = options.maintainIntervalMs ?? 15_000;
    if (!Number.isInteger(this.inboundCount) || this.inboundCount < 1 || this.inboundCount > 16) throw new RangeError('inboundCount must be 1..16');
    if (!Number.isInteger(this.outboundCount) || this.outboundCount < 1 || this.outboundCount > 16) throw new RangeError('outboundCount must be 1..16');
    if (!Number.isInteger(this.hopCount) || this.hopCount < 1 || this.hopCount > 7) throw new RangeError('hopCount must be 1..7');
    if (!Number.isInteger(this.maintainIntervalMs) || this.maintainIntervalMs < 1_000 || this.maintainIntervalMs > 600_000) throw new RangeError('maintainIntervalMs must be 1000..600000');
  }

  start(): void {
    this.startZeroHopInbound();
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.maintain().catch(error => this.emit('error', error));
    }, this.maintainIntervalMs);
    this.timer.unref();
    void this.maintain().catch(error => this.emit('error', error));
  }

  get zeroHopTunnelId(): number | undefined { return this.zeroHopInboundId; }

  currentInbound(): BuiltInboundTunnel {
    this.expire();
    const tunnel = this.inbound[0];
    if (!tunnel) throw new Error('No inbound tunnel is ready');
    return tunnel;
  }

  currentOutbound(): BuiltOutboundTunnel {
    this.expire();
    const tunnel = this.outbound[0];
    if (!tunnel) throw new Error('No outbound tunnel is ready');
    return tunnel;
  }

  /** Creates the 0-hop inbound used to receive the first outbound-build replies. */
  startZeroHopInbound(): number {
    if (this.zeroHopInboundId) return this.zeroHopInboundId;
    const tunnelId = randomInt(1, 0x1_0000_0000);
    this.transit.registerZeroHopInbound(tunnelId);
    this.zeroHopInboundId = tunnelId;
    return tunnelId;
  }

  async maintain(): Promise<void> {
    if (this.maintaining) return;
    this.maintaining = true;
    try {
      this.expire();
      const reply = this.inbound[0] ?? this.zeroHopReply();
      let changed = false;
      while (this.outbound.length < this.outboundCount) {
        const path = this.selectPath(this.hopCount, this.usedIdentities());
        const tunnel = await this.builder.buildOutbound(path, { gatewayIdentityHash: reply.gatewayIdentityHash, tunnelId: reply.gatewayTunnelId });
        this.outbound.push(tunnel);
        this.emit('outbound', tunnel);
        changed = true;
      }
      while (this.inbound.length < this.inboundCount) {
        const outbound = this.outbound[0];
        if (!outbound) throw new Error('An outbound tunnel is required before building inbound tunnels');
        const path = this.selectPath(this.hopCount, this.usedIdentities());
        const first = path[0]!;
        const tunnel = await this.builder.buildInbound(path, {
          sendBuild: async message => {
            const garlic = wrapEciesRouterGarlicMessage(message, first.encryptionPublicKey);
            await this.sendThroughOutbound(outbound, garlic, { type: 'router', identityHash: first.identityHash });
          },
        });
        this.inbound.push(tunnel);
        this.emit('inbound', tunnel);
        changed = true;
      }
      if (changed) this.emit('change');
    } finally { this.maintaining = false; }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.inbound.length = 0;
    this.outbound.length = 0;
    if (this.zeroHopInboundId) this.transit.removeZeroHopInbound(this.zeroHopInboundId);
    this.zeroHopInboundId = undefined;
  }

  private zeroHopReply(): { gatewayIdentityHash: Buffer; gatewayTunnelId: number } {
    const tunnelId = this.startZeroHopInbound();
    return { gatewayIdentityHash: this.identity.identityHash, gatewayTunnelId: tunnelId };
  }

  private usedIdentities(): Buffer[] {
    const hashes: Buffer[] = [];
    for (const tunnel of [...this.inbound, ...this.outbound]) for (const hop of tunnel.hops) hashes.push(hop.identityHash);
    return hashes;
  }

  private expire(): void {
    const now = Date.now();
    for (let index = this.inbound.length - 1; index >= 0; index--) if (this.inbound[index]!.expiresAt <= now) this.inbound.splice(index, 1);
    for (let index = this.outbound.length - 1; index >= 0; index--) if (this.outbound[index]!.expiresAt <= now) this.outbound.splice(index, 1);
  }
}
