import { createHash } from 'node:crypto';
import { decodeDestinationBase64, parseDestination } from '../protocol/destination.ts';
import { b32AddressFromHash, parseB32Hostname } from '../util/encoding.ts';

/** Well-known jump destinations used to bootstrap naming when floodfill lookups are cold. */
export const BOOTSTRAP_HOSTS: Record<string, string> = {
  'i2p-projekt.i2p': '8ZAW~KzGFMUEj0pdchy6GQOOZbuzbqpWtiApEj8LHy2~O~58XKxRrA43cA23a9oDpNZDqWhRWEtehSnX5NoCwJcXWWdO1ksKEUim6cQLP-VpQyuZTIIqwSADwgoe6ikxZG0NGvy5FijgxF4EW9zg39nhUNKRejYNHhOBZKIX38qYyXoB8XCVJybKg89aMMPsCT884F0CLBKbHeYhpYGmhE4YW~aV21c5pebivvxeJPWuTBAOmYxAIgJE3fFU-fucQn9YyGUFa8F3t-0Vco-9qVNSEWfgrdXOdKT6orr3sfssiKo3ybRWdTpxycZ6wB4qHWgTSU5A-gOA3ACTCMZBsASN3W5cz6GRZCspQ0HNu~R~nJ8V06Mmw~iVYOu5lDvipmG6-dJky6XRxCedczxMM1GWFoieQ8Ysfuxq-j8keEtaYmyUQme6TcviCEvQsxyVirr~dTC-F8aZ~y2AlG5IJz5KD02nO6TRkI2fgjHhv9OZ9nskh-I2jxAzFP6Is1kyAAAA',
};

BOOTSTRAP_HOSTS['i2p-project.i2p'] = BOOTSTRAP_HOSTS['i2p-projekt.i2p']!;

export class HostsBook {
  private readonly names = new Map<string, Buffer>();

  constructor() {
    for (const [name, dest] of Object.entries(BOOTSTRAP_HOSTS)) this.add(name, dest);
  }

  add(name: string, destination: string | Buffer): void {
    const bytes = Buffer.isBuffer(destination) ? destination : decodeDestinationBase64(destination);
    parseDestination(bytes);
    this.names.set(normalizeHostname(name), Buffer.from(bytes));
  }

  get(name: string): Buffer | undefined {
    const bytes = this.names.get(normalizeHostname(name));
    return bytes ? Buffer.from(bytes) : undefined;
  }

  resolve(hostname: string): { destination?: Buffer; hash: Buffer } | undefined {
    const b32 = parseB32Hostname(hostname);
    if (b32) return { hash: b32 };
    const dest = this.get(hostname);
    if (dest) return { destination: dest, hash: createHash('sha256').update(dest).digest() };
    return undefined;
  }

  importHostsTxt(text: string): number {
    let count = 0;
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq < 1) continue;
      try { this.add(trimmed.slice(0, eq), trimmed.slice(eq + 1)); count++; }
      catch { /* skip malformed entries */ }
    }
    return count;
  }

  b32Of(name: string): string | undefined {
    const dest = this.get(name);
    if (!dest) return undefined;
    return b32AddressFromHash(createHash('sha256').update(dest).digest());
  }
}

export function normalizeHostname(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, '');
}
