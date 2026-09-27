/** Token-bucket limiter for outbound I2NP / tunnel bytes. rateBytesPerSec 0 disables limiting. */
export class TokenBucket {
  private tokens: number;
  private lastRefill: number;
  private readonly rate: number;
  private readonly burst: number;
  private waiting: Array<{ need: number; resolve: () => void; reject: (error: Error) => void }> = [];
  private timer: NodeJS.Timeout | undefined;
  private stopped = false;

  constructor(rateBytesPerSec: number, burstBytes?: number) {
    if (!Number.isFinite(rateBytesPerSec) || rateBytesPerSec < 0 || rateBytesPerSec > 1_000_000_000) {
      throw new RangeError('rateBytesPerSec must be 0..1000000000');
    }
    this.rate = rateBytesPerSec;
    this.burst = burstBytes ?? Math.max(rateBytesPerSec, 16_384);
    if (!Number.isFinite(this.burst) || this.burst < 1 || this.burst > 64_000_000) throw new RangeError('burstBytes must be 1..64000000');
    this.tokens = this.burst;
    this.lastRefill = Date.now();
  }

  get unlimited(): boolean { return this.rate === 0; }

  tryTake(bytes: number): boolean {
    if (this.unlimited) return true;
    this.assertBytes(bytes);
    this.refill();
    if (this.tokens < bytes) return false;
    this.tokens -= bytes;
    return true;
  }

  async take(bytes: number): Promise<void> {
    if (this.unlimited) return;
    this.assertBytes(bytes);
    if (this.stopped) throw new Error('Token bucket is stopped');
    this.refill();
    if (this.tokens >= bytes) {
      this.tokens -= bytes;
      return;
    }
    return new Promise((resolve, reject) => {
      this.waiting.push({ need: bytes, resolve, reject });
      this.schedule();
    });
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    const pending = this.waiting.splice(0);
    for (const waiter of pending) waiter.reject(new Error('Token bucket is stopped'));
  }

  private assertBytes(bytes: number): void {
    if (!Number.isInteger(bytes) || bytes < 0) throw new RangeError('byte count must be a non-negative integer');
  }

  private refill(): void {
    if (this.unlimited) return;
    const now = Date.now();
    const elapsed = Math.max(0, now - this.lastRefill);
    this.lastRefill = now;
    this.tokens = Math.min(this.burst, this.tokens + (this.rate * elapsed) / 1_000);
  }

  private schedule(): void {
    if (this.timer || this.stopped || !this.waiting.length) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.refill();
      while (this.waiting.length) {
        const next = this.waiting[0]!;
        if (this.tokens < next.need) break;
        this.tokens -= next.need;
        this.waiting.shift();
        next.resolve();
      }
      if (this.waiting.length) this.schedule();
    }, 25);
    this.timer.unref();
  }
}
