/**
 * Salted PBKDF2 Password Hashing & Verification
 * Compatible across all modern browsers (Web Crypto API) and Node.js (crypto.subtle / pbkdf2Sync)
 * Algorithm: PBKDF2, SHA-512, 1000 iterations, 64-byte key (512-bit)
 * Format: `${saltHex}:${hashHex}`
 */

export async function hashPasswordWeb(password: string, existingSalt?: string): Promise<string> {
  const enc = new TextEncoder();
  let saltHex = existingSalt;

  if (!saltHex) {
    const saltBytes = new Uint8Array(16);
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(saltBytes);
    } else {
      // Node.js fallback
      try {
        const cryptoNode = await import('crypto');
        const buf = cryptoNode.randomBytes(16);
        saltBytes.set(buf);
      } catch {
        for (let i = 0; i < 16; i++) {
          saltBytes[i] = Math.floor(Math.random() * 256);
        }
      }
    }
    saltHex = Array.from(saltBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // Salt bytes matching Node.js pbkdf2Sync(password, saltHex, 1000, 64, 'sha512')
  const saltBytesForPbkdf2 = enc.encode(saltHex);

  const subtle = typeof window !== 'undefined' && window.crypto?.subtle
    ? window.crypto.subtle
    : (await import('crypto')).webcrypto.subtle;

  const keyMaterial = await subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytesForPbkdf2,
      iterations: 1000,
      hash: 'SHA-512',
    },
    keyMaterial,
    512 // 64 bytes
  );

  const hashHex = Array.from(new Uint8Array(derivedBits))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return `${saltHex}:${hashHex}`;
}

export async function verifyPasswordWeb(password: string, combinedHash?: string): Promise<boolean> {
  if (!combinedHash) return false;
  if (!combinedHash.includes(':')) {
    return password === combinedHash;
  }
  const [saltHex, expectedHashHex] = combinedHash.split(':');
  if (!saltHex || !expectedHashHex) return false;

  try {
    const computed = await hashPasswordWeb(password, saltHex);
    const [, computedHashHex] = computed.split(':');
    return computedHashHex === expectedHashHex;
  } catch (err) {
    console.error('Password verification error:', err);
    return false;
  }
}
