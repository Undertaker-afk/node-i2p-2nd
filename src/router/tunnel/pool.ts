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
  exploratoryCount?: number;
  exploratoryHopCount?: number;
  testPair?: (outbound: BuiltOutboundTunnel, inbound: BuiltInboundTunnel) => Promise<boolean>;
  recordHop?: (identityHash: Buffer, success: boolean) => void;
};

/** Maintains inbound/outbound client tunnels plus a 1-hop exploratory pair for netDb. */
export class TunnelPool extends EventEmitter {
  readonly inbound: BuiltInboundTunnel[] = [];
  readonly outbound: BuiltOutboundTunnel[] = [];
  readonly exploratoryInbound: BuiltInboundTunnel[] = [];
  readonly exploratoryOutbound: BuiltOutboundTunnel[] = [];
  private zeroHopInboundId: number | undefined;
  private readonly identity: RouterIdentityKeys;
  private readonly builder: ShortTunnelBuildCreator;
  private readonly transit: TransitTunnelService;
  private readonly selectPath: TunnelPoolOptions['selectPath'];
  private readonly sendThroughOutbound: TunnelPoolOptions['sendThroughOutbound'];
  private readonly inboundCount: number;
  private readonly outboundCount: number;
  private readonly hopCount: number;
  private readonly exploratoryCount: number;
  private readonly exploratoryHopCount: number;
  private readonly maintainIntervalMs: number;
  private readonly testPair: TunnelPoolOptions['testPair'];
  private readonly recordHop: TunnelPoolOptions['recordHop'];
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
    this.exploratoryCount = options.exploratoryCount ?? 1;
    this.exploratoryHopCount = options.exploratoryHopCount ?? 1;
    this.maintainIntervalMs = options.maintainIntervalMs ?? 15_000;
    this.testPair = options.testPair;
    this.recordHop = options.recordHop;
    if (!Number.isInteger(this.inboundCount) || this.inboundCount < 1 || this.inboundCount > 16) throw new RangeError('inboundCount must be 1..16');
    if (!Number.isInteger(this.outboundCount) || this.outboundCount < 1 || this.outboundCount > 16) throw new RangeError('outboundCount must be 1..16');
    if (!Number.isInteger(this.hopCount) || this.hopCount < 1 || this.hopCount > 7) throw new RangeError('hopCount must be 1..7');
    if (!Number.isInteger(this.exploratoryCount) || this.exploratoryCount < 0 || this.exploratoryCount > 8) throw new RangeError('exploratoryCount must be 0..8');
    if (!Number.isInteger(this.exploratoryHopCount) || this.exploratoryHopCount < 1 || this.exploratoryHopCount > 3) throw new RangeError('exploratoryHopCount must be 1..3');
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

  /** Prefers a tested 1-hop exploratory outbound for netDb lookups. */
  currentExploratoryOutbound(): BuiltOutboundTunnel {
    this.expire();
    return this.exploratoryOutbound[0] ?? this.currentOutbound();
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
        const tunnel = await this.buildOutbound(this.hopCount, reply);
        if (!tunnel) break;
        this.outbound.push(tunnel);
        this.emit('outbound', tunnel);
        changed = true;
      }
      while (this.inbound.length < this.inboundCount) {
        const tunnel = await this.buildInbound(this.hopCount, this.outbound[0]);
        if (!tunnel) break;
        this.inbound.push(tunnel);
        this.emit('inbound', tunnel);
        changed = true;
      }
      while (this.exploratoryOutbound.length < this.exploratoryCount) {
        const tunnel = await this.buildOutbound(this.exploratoryHopCount, reply);
        if (!tunnel) break;
        this.exploratoryOutbound.push(tunnel);
        this.emit('exploratoryOutbound', tunnel);
        changed = true;
      }
      while (this.exploratoryInbound.length < this.exploratoryCount) {
        const via = this.exploratoryOutbound[0] ?? this.outbound[0];
        const tunnel = await this.buildInbound(this.exploratoryHopCount, via);
        if (!tunnel) break;
        this.exploratoryInbound.push(tunnel);
        this.emit('exploratoryInbound', tunnel);
        changed = true;
      }
      if (this.testPair && this.outbound[0] && this.inbound[0]) {
        const ok = await this.runTest(this.outbound[0], this.inbound[0]);
        if (!ok) {
          this.dropFailed(this.outbound, 0);
          this.dropFailed(this.inbound, 0);
          changed = true;
        }
      }
      if (changed) this.emit('change');
    } finally { this.maintaining = false; }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.inbound.length = 0;
    this.outbound.length = 0;
    this.exploratoryInbound.length = 0;
    this.exploratoryOutbound.length = 0;
    if (this.zeroHopInboundId) this.transit.removeZeroHopInbound(this.zeroHopInboundId);
    this.zeroHopInboundId = undefined;
  }

  private async buildOutbound(hopCount: number, reply: { gatewayIdentityHash: Buffer; gatewayTunnelId: number }): Promise<BuiltOutboundTunnel | undefined> {
    try {
      const path = this.selectPath(hopCount, this.usedIdentities());
      const tunnel = await this.builder.buildOutbound(path, { gatewayIdentityHash: reply.gatewayIdentityHash, tunnelId: reply.gatewayTunnelId });
      this.noteHops(tunnel.hops, true);
      return tunnel;
    } catch (error) {
      this.emit('buildError', error);
      return undefined;
    }
  }

  private async buildInbound(hopCount: number, outbound: BuiltOutboundTunnel | undefined): Promise<BuiltInboundTunnel | undefined> {
    if (!outbound) return undefined;
    try {
      const path = this.selectPath(hopCount, this.usedIdentities());
      const first = path[0]!;
      const tunnel = await this.builder.buildInbound(path, {
        sendBuild: async message => {
          const garlic = wrapEciesRouterGarlicMessage(message, first.encryptionPublicKey);
          await this.sendThroughOutbound(outbound, garlic, { type: 'router', identityHash: first.identityHash });
        },
      });
      this.noteHops(tunnel.hops, true);
      return tunnel;
    } catch (error) {
      this.emit('buildError', error);
      return undefined;
    }
  }

  private async runTest(outbound: BuiltOutboundTunnel, inbound: BuiltInboundTunnel): Promise<boolean> {
    if (!this.testPair) return true;
    try {
      const ok = await this.testPair(outbound, inbound);
      this.noteHops([...outbound.hops, ...inbound.hops], ok);
      return ok;
    } catch (error) {
      this.noteHops([...outbound.hops, ...inbound.hops], false);
      this.emit('testError', error);
      return false;
    }
  }

  private noteHops(hops: { identityHash: Buffer }[], success: boolean): void {
    if (!this.recordHop) return;
    for (const hop of hops) this.recordHop(hop.identityHash, success);
  }

  private dropFailed<T>(list: T[], index: number): void {
    if (index >= 0 && index < list.length) list.splice(index, 1);
  }

  private zeroHopReply(): { gatewayIdentityHash: Buffer; gatewayTunnelId: number } {
    const tunnelId = this.startZeroHopInbound();
    return { gatewayIdentityHash: this.identity.identityHash, gatewayTunnelId: tunnelId };
  }

  private usedIdentities(): Buffer[] {
    const hashes: Buffer[] = [];
    for (const tunnel of [...this.inbound, ...this.outbound, ...this.exploratoryInbound, ...this.exploratoryOutbound]) {
      for (const hop of tunnel.hops) hashes.push(hop.identityHash);
    }
    return hashes;
  }

  private expire(): void {
    const now = Date.now();
    for (const list of [this.inbound, this.exploratoryInbound]) {
      for (let index = list.length - 1; index >= 0; index--) if (list[index]!.expiresAt <= now) list.splice(index, 1);
    }
    for (const list of [this.outbound, this.exploratoryOutbound]) {
      for (let index = list.length - 1; index >= 0; index--) if (list[index]!.expiresAt <= now) list.splice(index, 1);
    }
  }
}
