import { createPublicKey, diffieHellman, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { hsalsa, xsalsa20poly1305 } from "@noble/ciphers/salsa.js";
import { u32, u8, utf8ToBytes } from "@noble/ciphers/utils.js";

export const keyLength = 32;

const nonceLength = 24;
const sigma = "expand 32-byte k";

export interface BoxKeyPair {
	readonly publicKey: Uint8Array;
	readonly privateKey: KeyObject;
}

const rawPublicKeyOf = (publicKey: KeyObject): Uint8Array => {
	const { x } = publicKey.export({ format: "jwk" });
	const bytes = x === undefined ? new Uint8Array() : new Uint8Array(Buffer.from(x, "base64url"));

	if (bytes.length !== keyLength) {
		throw new Error("x25519 public key export was malformed");
	}

	return bytes;
};

export const generateKeyPair = (): BoxKeyPair => {
	const { publicKey, privateKey } = generateKeyPairSync("x25519");

	return { publicKey: rawPublicKeyOf(publicKey), privateKey };
};

export const sharedKey = (theirPublicKey: Uint8Array, privateKey: KeyObject): Uint8Array => {
	const peer = createPublicKey({
		key: { kty: "OKP", crv: "X25519", x: Buffer.from(theirPublicKey).toString("base64url") },
		format: "jwk",
	});
	const secret = new Uint8Array(diffieHellman({ privateKey, publicKey: peer }));
	const derived = new Uint32Array(keyLength / 4);

	hsalsa(u32(utf8ToBytes(sigma)), u32(secret), u32(new Uint8Array(16)), derived);

	return u8(derived);
};

export const seal = (key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array =>
	xsalsa20poly1305(key, nonce).encrypt(plaintext);

export const open = (key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array | undefined => {
	const cipher = xsalsa20poly1305(key, nonce);

	try {
		return cipher.decrypt(ciphertext);
	} catch {
		return undefined;
	}
};

export const incrementNonce = (nonce: Uint8Array): Uint8Array => {
	const next = new Uint8Array(nonce);
	let carry = 1;

	for (let index = 0; index < next.length && carry > 0; index += 1) {
		const sum = (next[index] ?? 0) + carry;

		next[index] = sum & 0xff;
		carry = sum >>> 8;
	}

	return next;
};

export const randomNonce = (): Uint8Array => new Uint8Array(randomBytes(nonceLength));
