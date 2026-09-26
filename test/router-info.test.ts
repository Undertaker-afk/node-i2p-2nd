import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { parseRouterInfo, verifyRouterInfoSignature } from '../src/router/protocol/router-info.ts';
import { VerifiedRouterInfoStore } from '../src/router/netdb/store.ts';
import { encodeDate, encodeString } from '../src/router/protocol/common.ts';

function mapping(entries: Array<[string, string]>): Buffer {
  const body = Buffer.concat(entries.flatMap(([key, value]) => [encodeString(key), Buffer.from('='), encodeString(value), Buffer.from(';')]));
  const size = Buffer.alloc(2); size.writeUInt16BE(body.length); return Buffer.concat([size, body]);
}
function makeRouterInfo(opts: { options?: Array<[string, string]>; transportOptions?: Array<[string, string]>; certificateType?: number } = {}): Buffer {
  const identity = Buffer.alloc(387); identity[384] = opts.certificateType ?? 0;
  const transport = Buffer.concat([Buffer.from([5]), Buffer.from('NTCP2')]);
  const address = Buffer.concat([Buffer.from([3]), encodeDate(0), transport, mapping(opts.transportOptions ?? [['host', '127.0.0.1'], ['port', '12345']])]);
  const fields = Buffer.concat([
    identity, encodeDate(1_800_000_000_000), Buffer.from([1]), address,
    Buffer.from([0]), mapping(opts.options ?? [['netId', '2'], ['router.version', '0.9.68']]),
  ]);
  return Buffer.concat([fields, Buffer.alloc(40)]);
}

function makeSignedRouterInfo(published: number, pair = generateKeyPairSync('ed25519'), netId = '2'): { encoded: Buffer; pair: ReturnType<typeof generateKeyPairSync> } {
  const rawPublicKey = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const identity = Buffer.alloc(391); rawPublicKey.copy(identity, 352);
  identity[384] = 5; identity.writeUInt16BE(4, 385); identity.writeUInt16BE(7, 387); identity.writeUInt16BE(4, 389);
  const unsigned = Buffer.concat([identity, encodeDate(published), Buffer.from([0, 0]), mapping([['netId', netId]])]);
  return { encoded: Buffer.concat([unsigned, sign(null, unsigned, pair.privateKey)]), pair };
}

test('parses legacy RouterInfo envelope, address, options, and identity hash', () => {
  const encoded = makeRouterInfo(); const parsed = parseRouterInfo(encoded);
  assert.equal(parsed.identity.length, 387);
  assert.equal(parsed.identityHash.toString('hex'), createHash('sha256').update(encoded.subarray(0, 387)).digest('hex'));
  assert.equal(parsed.published, 1_800_000_000_000);
  assert.equal(parsed.addresses[0]?.transport, 'NTCP2');
  assert.equal(parsed.addresses[0]?.options.get('port'), '12345');
  assert.equal(parsed.options.get('netId'), '2');
  assert.equal(parsed.signatureType, 0);
  assert.equal(parsed.signature.length, 40);
  assert.deepEqual(parsed.signedData, encoded.subarray(0, encoded.length - 40));
});

test('verifies Ed25519 RouterInfo signatures against identity signing key', () => {
  const pair = generateKeyPairSync('ed25519');
  const rawPublicKey = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const identity = Buffer.alloc(391);
  rawPublicKey.copy(identity, 352); identity[384] = 5; identity.writeUInt16BE(4, 385);
  identity.writeUInt16BE(7, 387); identity.writeUInt16BE(4, 389);
  const unsigned = Buffer.concat([
    identity, encodeDate(1_800_000_000_000), Buffer.from([0, 0]),
    mapping([['netId', '2'], ['router.version', '0.9.68']]),
  ]);
  const encoded = Buffer.concat([unsigned, sign(null, unsigned, pair.privateKey)]);
  const info = parseRouterInfo(encoded);
  assert.equal(info.signatureType, 7);
  assert.equal(verifyRouterInfoSignature(info), true);
  const changed = Buffer.from(encoded); changed[398] = changed[398]! ^ 1;
  assert.equal(verifyRouterInfoSignature(parseRouterInfo(changed)), false);
});

test('verified RouterInfo store rejects bad records, deduplicates versions, and is bounded', () => {
  const { encoded, pair } = makeSignedRouterInfo(1000);
  const info = parseRouterInfo(encoded);
  const store = new VerifiedRouterInfoStore(1);
  assert.equal(store.store(info), true);
  assert.equal(store.store(info), false);
  const retrieved = store.get(info.identityHash)!;
  retrieved.identity.fill(0);
  assert.notDeepEqual(store.get(info.identityHash)?.identity, retrieved.identity);
  const newer = parseRouterInfo(makeSignedRouterInfo(2000, pair).encoded);
  assert.equal(store.store(newer), true);
  assert.equal(store.get(info.identityHash)?.published, 2000);
  const other = parseRouterInfo(makeSignedRouterInfo(3000).encoded);
  assert.equal(store.store(other), true);
  assert.equal(store.size, 1);
  assert.equal(store.get(info.identityHash), undefined);
  const badBytes = Buffer.from(encoded); badBytes[398] = badBytes[398]! ^ 1;
  assert.throws(() => store.store(parseRouterInfo(badBytes)), /invalid/);
});

test('verified store rejects records signed for a different network', () => {
  const otherNetwork = parseRouterInfo(makeSignedRouterInfo(1000, undefined, '3').encoded);
  assert.throws(() => new VerifiedRouterInfoStore().store(otherNetwork), /network ID/);
});

test('legacy signature types fail closed in the Ed25519 verifier', () => {
  assert.throws(() => verifyRouterInfoSignature(parseRouterInfo(makeRouterInfo())), /not implemented/);
});

test('RouterInfo parser rejects malformed signatures, duplicates, sorting and certificates', () => {
  const truncated = makeRouterInfo().subarray(0, makeRouterInfo().length - 1);
  assert.throws(() => parseRouterInfo(truncated), /signature size mismatch/);
  assert.throws(() => parseRouterInfo(makeRouterInfo({ options: [['z', '1'], ['a', '2']] })), /not sorted/);
  assert.throws(() => parseRouterInfo(makeRouterInfo({ options: [['same', '1'], ['same', '2']] })), /Duplicate mapping key/);
  assert.throws(() => parseRouterInfo(makeRouterInfo({ certificateType: 1 })), /Unsupported RouterIdentity certificate/);
});
