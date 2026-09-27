import { createHash } from 'node:crypto';

/** UTC date string used for netDb keyspace rotation: "yyyyMMdd". */
export function routingKeyDate(nowMs = Date.now()): string {
  const date = new Date(nowMs);
  return `${date.getUTCFullYear()}${String(date.getUTCMonth() + 1).padStart(2, '0')}${String(date.getUTCDate()).padStart(2, '0')}`;
}

/**
 * Floodfills store and answer by routing key, not raw hash:
 * routingKey = SHA256(key || ASCII yyyyMMdd UTC). Closeness is XOR against the floodfill's identity hash.
 */
export function routingKey(key: Buffer, nowMs = Date.now()): Buffer {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('netDb key must be 32 bytes');
  return createHash('sha256').update(key).update(routingKeyDate(nowMs), 'ascii').digest();
}

/** Negative when `a` is XOR-closer to `target` than `b`. */
export function compareXorDistance(target: Buffer, a: Buffer, b: Buffer): number {
  for (let index = 0; index < 32; index++) {
    const left = a[index]! ^ target[index]!;
    const right = b[index]! ^ target[index]!;
    if (left !== right) return left - right;
  }
  return 0;
}
