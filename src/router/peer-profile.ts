const FAIL_WINDOW_MS = 15 * 60 * 1000;
const EXCLUDE_FAILURES = 3;

export type PeerProfileSnapshot = {
  identityHash: Buffer;
  success: number;
  fail: number;
  consecutiveFailures: number;
  rttMs: number;
  lastSuccess: number;
  lastFailure: number;
  lastSeen: number;
  score: number;
};

type Profile = {
  success: number;
  fail: number;
  consecutiveFailures: number;
  rttEma: number;
  lastSuccess: number;
  lastFailure: number;
  lastSeen: number;
};

function keyOf(hash: Buffer): string {
  if (!Buffer.isBuffer(hash) || hash.length !== 32) throw new Error('Router identity hash must be 32 bytes');
  return hash.toString('hex');
}

function empty(): Profile {
  return { success: 0, fail: 0, consecutiveFailures: 0, rttEma: 0, lastSuccess: 0, lastFailure: 0, lastSeen: 0 };
}

/** Tracks per-peer tunnel and transport outcomes for hop selection. */
export class PeerProfiler {
  private readonly profiles = new Map<string, Profile>();

  get size(): number { return this.profiles.size; }

  recordSuccess(identityHash: Buffer, rttMs?: number): void {
    const profile = this.touch(identityHash);
    profile.success++;
    profile.consecutiveFailures = 0;
    profile.lastSuccess = profile.lastSeen;
    if (rttMs !== undefined) {
      if (!Number.isFinite(rttMs) || rttMs < 0) throw new RangeError('rttMs must be a non-negative number');
      profile.rttEma = profile.rttEma === 0 ? rttMs : profile.rttEma * 0.8 + rttMs * 0.2;
    }
  }

  recordFailure(identityHash: Buffer): void {
    const profile = this.touch(identityHash);
    profile.fail++;
    profile.consecutiveFailures++;
    profile.lastFailure = profile.lastSeen;
  }

  score(identityHash: Buffer): number {
    return this.scoreOf(this.profiles.get(keyOf(identityHash)) ?? empty());
  }

  /** Recently failing peers are skipped when enough alternatives exist. */
  isUnusable(identityHash: Buffer, now = Date.now()): boolean {
    const profile = this.profiles.get(keyOf(identityHash));
    if (!profile) return false;
    return profile.consecutiveFailures >= EXCLUDE_FAILURES && now - profile.lastFailure < FAIL_WINDOW_MS;
  }

  rank(identityHashes: readonly Buffer[], now = Date.now()): Buffer[] {
    const scored = identityHashes.map(hash => {
      const profile = this.profiles.get(keyOf(hash)) ?? empty();
      const unusable = profile.consecutiveFailures >= EXCLUDE_FAILURES && now - profile.lastFailure < FAIL_WINDOW_MS;
      return { hash, score: unusable ? -1 : this.scoreOf(profile) + Math.random() * 0.01 };
    });
    scored.sort((left, right) => right.score - left.score);
    return scored.map(entry => entry.hash);
  }

  snapshot(): PeerProfileSnapshot[] {
    return [...this.profiles.entries()].map(([hex, profile]) => ({
      identityHash: Buffer.from(hex, 'hex'),
      success: profile.success,
      fail: profile.fail,
      consecutiveFailures: profile.consecutiveFailures,
      rttMs: profile.rttEma,
      lastSuccess: profile.lastSuccess,
      lastFailure: profile.lastFailure,
      lastSeen: profile.lastSeen,
      score: this.scoreOf(profile),
    }));
  }

  private touch(identityHash: Buffer): Profile {
    const key = keyOf(identityHash);
    let profile = this.profiles.get(key);
    if (!profile) {
      profile = empty();
      this.profiles.set(key, profile);
    }
    profile.lastSeen = Date.now();
    return profile;
  }

  private scoreOf(profile: Profile): number {
    const reliability = (profile.success + 1) / (profile.fail + 1);
    const latency = 1 / (1 + profile.rttEma / 1_000);
    return reliability * latency;
  }
}
