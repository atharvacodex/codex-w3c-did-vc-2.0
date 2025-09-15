const crypto = require('crypto');

const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(buffer) {
  let digits = [0];
  for (let i = 0; i < buffer.length; i++) {
    let carry = buffer[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  for (let k = 0; k < buffer.length && buffer[k] === 0; k++) {
    digits.push(0);
  }
  return digits.reverse().map((d) => alphabet[d]).join('');
}

function toBase64url(buffer) {
  return Buffer.from(buffer).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function fromBase64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

async function main() {
  const { subtle } = crypto.webcrypto;
  const keyPair = await subtle.generateKey({ name: 'Ed25519', namedCurve: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKeyBytes = new Uint8Array(await subtle.exportKey('raw', keyPair.publicKey));

  const multicodecPrefix = Uint8Array.from([0xed, 0x01]);
  const prefixed = new Uint8Array(multicodecPrefix.length + publicKeyBytes.length);
  prefixed.set(multicodecPrefix, 0);
  prefixed.set(publicKeyBytes, multicodecPrefix.length);
  const fingerprint = 'z' + base58Encode(prefixed);
  const did = `did:key:${fingerprint}`;

  const didDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1'
    ],
    id: did,
    verificationMethod: [
      {
        id: `${did}#${fingerprint}`,
        type: 'Multikey',
        controller: did,
        publicKeyMultibase: fingerprint
      }
    ],
    authentication: [`${did}#${fingerprint}`],
    assertionMethod: [`${did}#${fingerprint}`]
  };
  console.log('DID Document:', JSON.stringify(didDocument, null, 2));

  const vc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:' + crypto.randomUUID(),
    type: ['VerifiableCredential'],
    issuer: did,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: did,
      name: 'Alice'
    }
  };

  const header = toBase64url(JSON.stringify({ alg: 'EdDSA', kid: `${did}#${fingerprint}` }));
  const payload = toBase64url(JSON.stringify(vc));
  const data = Buffer.from(`${header}.${payload}`);
  const signature = new Uint8Array(await subtle.sign('Ed25519', keyPair.privateKey, data));
  const jws = `${header}.${payload}.${toBase64url(signature)}`;
  console.log('Credential JWS:', jws);

  const parts = jws.split('.');
  const signedData = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sigBytes = new Uint8Array(fromBase64url(parts[2]));
  const verified = await subtle.verify('Ed25519', keyPair.publicKey, sigBytes, signedData);
  console.log('Verified:', verified);

  const decodedPayload = JSON.parse(fromBase64url(parts[1]).toString());
  console.log('Decoded Credential:', JSON.stringify(decodedPayload, null, 2));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

