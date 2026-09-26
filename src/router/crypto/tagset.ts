import { hkdf } from './x25519.ts';

const ZERO = Buffer.alloc(0);

export type SessionTagEntry = { tag: Buffer; index: number; key: Buffer };

/** Signal-style session tag and symmetric-key ratchet used by ECIES dest sessions. */
export class RatchetTagSet {
  private nextRootKey = Buffer.alloc(32);
  private sessTagCk = Buffer.alloc(32);
  private sessTagConstant = Buffer.alloc(32);
  private symmKeyCk = Buffer.alloc(32);
  private currentSymm = Buffer.alloc(64);
  private nextIndex = 0;
  private nextSymmIndex = 0;
  private readonly pendingKeys = new Map<number, Buffer>();
  tagSetId = 0;

  dhInitialize(rootKey: Buffer, k: Buffer): void {
    if (!Buffer.isBuffer(rootKey) || rootKey.length !== 32 || !Buffer.isBuffer(k) || k.length !== 32) throw new Error('DH_INITIALIZE keys must be 32 bytes');
    const step = hkdf(rootKey, k, 'KDFDHRatchetStep', 64);
    this.nextRootKey = Buffer.from(step.subarray(0, 32));
    const chains = hkdf(step.subarray(32, 64), ZERO, 'TagAndKeyGenKeys', 64);
    this.sessTagCk = Buffer.from(chains.subarray(0, 32));
    this.symmKeyCk = Buffer.from(chains.subarray(32, 64));
    this.nextSessionTagRatchet();
  }

  nextSessionTagRatchet(): void {
    const init = hkdf(this.sessTagCk, ZERO, 'STInitialization', 64);
    this.sessTagCk = Buffer.from(init.subarray(0, 32));
    this.sessTagConstant = Buffer.from(init.subarray(32, 64));
    this.nextIndex = 0;
    this.nextSymmIndex = 0;
    this.pendingKeys.clear();
  }

  get nextRoot(): Buffer { return Buffer.from(this.nextRootKey); }
  get nextIndexValue(): number { return this.nextIndex; }

  nextTag(): SessionTagEntry {
    const index = this.nextIndex;
    const generated = hkdf(this.sessTagCk, this.sessTagConstant, 'SessionTagKeyGen', 64);
    this.sessTagCk = Buffer.from(generated.subarray(0, 32));
    const tag = Buffer.from(generated.subarray(32, 40));
    this.nextIndex = index + 1;
    if (this.nextIndex > 65_535) throw new Error('Session tag set is exhausted');
    return { tag, index, key: this.symmKey(index) };
  }

  generateWindow(count: number): SessionTagEntry[] {
    if (!Number.isInteger(count) || count < 1 || count > 800) throw new RangeError('Tag window size is out of range');
    return Array.from({ length: count }, () => this.nextTag());
  }

  symmKey(index: number): Buffer {
    if (!Number.isInteger(index) || index < 0) throw new RangeError('Symmetric key index is invalid');
    if (index < this.nextSymmIndex) {
      const cached = this.pendingKeys.get(index);
      if (!cached) throw new Error(`Missing symmetric key for index ${index}`);
      this.pendingKeys.delete(index);
      return Buffer.from(cached);
    }
    while (this.nextSymmIndex <= index) {
      const generated = hkdf(this.nextSymmIndex === 0 ? this.symmKeyCk : this.currentSymm.subarray(0, 32), ZERO, 'SymmetricRatchet', 64);
      this.currentSymm = Buffer.from(generated);
      if (this.nextSymmIndex !== index) this.pendingKeys.set(this.nextSymmIndex, Buffer.from(generated.subarray(32, 64)));
      this.nextSymmIndex++;
    }
    return Buffer.from(this.currentSymm.subarray(32, 64));
  }
}
