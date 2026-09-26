import { createHash, generateKeyPairSync, randomFillSync, type KeyObject } from 'node:crypto';

const KEY_CERTIFICATE = 5;
const EDDSA_SHA512_ED25519 = 7;
const X25519 = 4;

export type RouterIdentityKeys = {
  identity: Buffer;
  identityHash: Buffer;
  signingPrivateKey: KeyObject;
  encryptionPrivateKey: KeyObject;
};

function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ format: 'der', type: 'spki' });
  if (der.length < 32) throw new Error('Unexpected public key encoding');
  return Buffer.from(der.subarray(der.length - 32));
}

/** Creates an in-memory Ed25519/X25519 RouterIdentity. Key persistence is deliberately separate. */
export function createRouterIdentity(): RouterIdentityKeys {
  const signing = generateKeyPairSync('ed25519');
  const encryption = generateKeyPairSync('x25519');
  const identity = Buffer.alloc(391);
  rawPublicKey(encryption.publicKey).copy(identity, 0);
  // Spec-recommended compressible padding: ten copies of independent random bytes.
  const padding = randomFillSync(Buffer.alloc(32));
  for (let offset = 32; offset < 352; offset += padding.length) padding.copy(identity, offset);
  rawPublicKey(signing.publicKey).copy(identity, 352);
  identity[384] = KEY_CERTIFICATE;
  identity.writeUInt16BE(4, 385);
  identity.writeUInt16BE(EDDSA_SHA512_ED25519, 387);
  identity.writeUInt16BE(X25519, 389);
  return {
    identity,
    identityHash: createHash('sha256').update(identity).digest(),
    signingPrivateKey: signing.privateKey,
    encryptionPrivateKey: encryption.privateKey,
  };
}
