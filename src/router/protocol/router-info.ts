import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import { ByteReader, encodeDate, encodeString } from './common.ts';
import type { RouterIdentityKeys } from '../identity.ts';

export type RouterAddress = { cost: number; expiration: number; transport: string; options: Map<string, string> };
export type RouterInfo = {
  identity: Buffer;
  identityHash: Buffer;
  published: number;
  addresses: RouterAddress[];
  peers: Buffer[];
  options: Map<string, string>;
  signatureType: number;
  signature: Buffer;
  signedData: Buffer;
};

const SIGNATURE_LENGTHS = new Map<number, number>([
  [0, 40], [1, 64], [2, 96], [3, 132], [4, 256], [5, 384], [6, 512],
  [7, 64], [8, 64],
]);
const CERT_NULL = 0;
const CERT_KEY = 5;

function encodeMapping(entries: Map<string, string>): Buffer {
  const keys = [...entries.keys()].sort();
  const chunks: Buffer[] = [];
  for (const key of keys) {
    const value = entries.get(key)!;
    chunks.push(encodeString(key), Buffer.from('='), encodeString(value), Buffer.from(';'));
  }
  const body = Buffer.concat(chunks);
  if (body.length > 0xffff) throw new RangeError('Mapping exceeds 65535 bytes');
  const length = Buffer.allocUnsafe(2); length.writeUInt16BE(body.length);
  return Buffer.concat([length, body]);
}

/** Builds and Ed25519-signs a RouterInfo using a matching locally-held identity. */
export function createRouterInfoRecord(
  keys: RouterIdentityKeys,
  published: number,
  addresses: readonly RouterAddress[],
  options: Map<string, string>,
): Buffer {
  if (keys.identity.length !== 391 || keys.identity[384] !== CERT_KEY) throw new Error('Unsupported local RouterIdentity format');
  if (!Number.isSafeInteger(published) || published < 0) throw new RangeError('published must be a non-negative safe integer');
  if (addresses.length > 255) throw new RangeError('RouterInfo supports at most 255 addresses');
  const addressChunks: Buffer[] = [];
  for (const address of addresses) {
    if (!Number.isInteger(address.cost) || address.cost < 0 || address.cost > 255) throw new RangeError('RouterAddress cost must be 0..255');
    addressChunks.push(Buffer.from([address.cost]), encodeDate(address.expiration), encodeString(address.transport), encodeMapping(address.options));
  }
  const signedData = Buffer.concat([
    keys.identity, encodeDate(published), Buffer.from([addresses.length]), ...addressChunks,
    Buffer.from([0]), encodeMapping(options),
  ]);
  const encoded = Buffer.concat([signedData, sign(null, signedData, keys.signingPrivateKey)]);
  if (!verifyRouterInfoSignature(parseRouterInfo(encoded))) throw new Error('Local signing key does not match RouterIdentity');
  return encoded;
}

function readMapping(reader: ByteReader): Map<string, string> {
  const byteLength = reader.readUInt16();
  const mappingReader = new ByteReader(reader.readBytes(byteLength), 65_535);
  const result = new Map<string, string>();
  while (mappingReader.remaining) {
    const key = mappingReader.readString();
    if (mappingReader.readUInt8() !== 0x3d) throw new Error('Mapping entry is missing equals delimiter');
    const value = mappingReader.readString();
    if (mappingReader.readUInt8() !== 0x3b) throw new Error('Mapping entry is missing semicolon delimiter');
    if (result.has(key)) throw new Error(`Duplicate mapping key: ${key}`);
    result.set(key, value);
  }
  return result;
}

/** Parses a RouterInfo envelope without asserting its signature is valid. */
export function parseRouterInfo(encoded: Buffer): RouterInfo {
  const reader = new ByteReader(encoded, 1_048_576);
  if (reader.remaining < 387 + 8 + 1 + 1 + 2 + 40) throw new Error('RouterInfo is too short');

  // RouterIdentity has a fixed 384-byte key area, certificate type, and 2-byte cert length.
  const identityPrefix = reader.readBytes(387);
  const certificateLength = identityPrefix.readUInt16BE(385);
  if (certificateLength > reader.remaining) throw new Error('RouterIdentity certificate exceeds RouterInfo');
  const certificateBody = reader.readBytes(certificateLength);
  const identity = Buffer.concat([identityPrefix, certificateBody]);
  const certificateType = identityPrefix[384]!;
  let signatureType = 0; // Legacy NULL-certificate identities use DSA-SHA1.
  if (certificateType === CERT_KEY) {
    if (certificateLength < 4) throw new Error('Key certificate is shorter than its type fields');
    signatureType = certificateBody.readUInt16BE(0);
  } else if (certificateType !== CERT_NULL) {
    throw new Error(`Unsupported RouterIdentity certificate type ${certificateType}`);
  }
  const signatureLength = SIGNATURE_LENGTHS.get(signatureType);
  if (signatureLength === undefined) throw new Error(`Unsupported RouterInfo signature type ${signatureType}`);

  const published = reader.readDate();
  const addressCount = reader.readUInt8();
  const addresses: RouterAddress[] = [];
  for (let i = 0; i < addressCount; i++) {
    const cost = reader.readUInt8();
    const expiration = reader.readDate();
    const transport = reader.readString();
    if (!transport || /[\0\r\n]/.test(transport)) throw new Error('Invalid RouterAddress transport name');
    const options = readMapping(reader);
    addresses.push({ cost, expiration, transport, options });
  }

  const peerCount = reader.readUInt8();
  if (peerCount > 0) throw new Error('RouterInfo restricted-route peer list is unsupported');
  const options = readMapping(reader);
  // RouterInfo options are signed in canonical key order.
  const optionKeys = [...options.keys()];
  for (let i = 1; i < optionKeys.length; i++) {
    if (optionKeys[i - 1]! > optionKeys[i]!) throw new Error('RouterInfo options are not sorted by key');
  }
  if (reader.remaining !== signatureLength) throw new Error(`RouterInfo signature size mismatch: expected ${signatureLength}, got ${reader.remaining}`);
  const signedLength = encoded.length - signatureLength;
  const signature = Buffer.from(reader.readBytes(signatureLength));
  reader.assertEnd();
  return {
    identity, identityHash: createHash('sha256').update(identity).digest(), published,
    addresses, peers: [], options, signatureType, signature,
    signedData: Buffer.from(encoded.subarray(0, signedLength)),
  };
}

/** Verifies an EdDSA-SHA512-Ed25519 RouterInfo signature; unsupported algorithms fail closed. */
export function verifyRouterInfoSignature(info: RouterInfo): boolean {
  if (info.signatureType !== 7) throw new Error(`Signature verification is not implemented for type ${info.signatureType}`);
  if (info.identity.length < 387 || info.identity[384] !== CERT_KEY) throw new Error('Ed25519 RouterIdentity requires a Key Certificate');
  const certificateLength = info.identity.readUInt16BE(385);
  if (certificateLength < 4 || info.identity.length !== 387 + certificateLength) throw new Error('Invalid RouterIdentity Key Certificate length');
  const signatureType = info.identity.readUInt16BE(387);
  const cryptoType = info.identity.readUInt16BE(389);
  if (signatureType !== 7) throw new Error('RouterIdentity signing key type does not match signature type');
  if (cryptoType !== 4) throw new Error(`Unsupported RouterIdentity encryption key type ${cryptoType}`);
  if (certificateLength !== 4) throw new Error('Unexpected excess data in Ed25519/X25519 Key Certificate');
  const publicKey = info.identity.subarray(352, 384);
  const derPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  const key = createPublicKey({ key: Buffer.concat([derPrefix, publicKey]), format: 'der', type: 'spki' });
  return verify(null, info.signedData, key, info.signature);
}
