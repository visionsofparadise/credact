import { createPrivateKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateKeyPair, incrementNonce, keyLength, open, randomNonce, seal, sharedKey } from "./keepassxcBox";

const aliceSecret = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const bobSecret = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const bobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const vectorNonce = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
const message =
	"be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c6129" +
	"6cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
	"048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705";
const expectedBox =
	"f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a" +
	"c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae" +
	"90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74" +
	"e355a5";

const bytesOf = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));

const hexOf = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

const base64UrlOf = (hex: string): string => Buffer.from(hex, "hex").toString("base64url");

const privateKeyOf = (secretHex: string, publicHex: string) =>
	createPrivateKey({
		key: { kty: "OKP", crv: "X25519", d: base64UrlOf(secretHex), x: base64UrlOf(publicHex) },
		format: "jwk",
	});

const alicePrivate = privateKeyOf(aliceSecret, alicePublic);
const bobPrivate = privateKeyOf(bobSecret, bobPublic);

describe("keepassxc box", () => {
	it("reproduces libsodium's crypto_box vector", () => {
		const sealed = seal(sharedKey(bytesOf(bobPublic), alicePrivate), bytesOf(vectorNonce), bytesOf(message));

		expect(hexOf(sealed)).toBe(expectedBox);
	});

	it("opens the vector from the other side of the exchange", () => {
		const opened = open(sharedKey(bytesOf(alicePublic), bobPrivate), bytesOf(vectorNonce), bytesOf(expectedBox));

		expect(opened === undefined ? undefined : hexOf(opened)).toBe(message);
	});

	it("derives the same key from either side", () => {
		expect(hexOf(sharedKey(bytesOf(bobPublic), alicePrivate))).toBe(
			hexOf(sharedKey(bytesOf(alicePublic), bobPrivate)),
		);
	});

	it("returns undefined when a ciphertext byte is flipped", () => {
		const tampered = bytesOf(expectedBox);

		tampered[40] = (tampered[40] ?? 0) ^ 0x01;

		expect(open(sharedKey(bytesOf(alicePublic), bobPrivate), bytesOf(vectorNonce), tampered)).toBeUndefined();
	});

	it("returns undefined when the nonce differs", () => {
		const otherNonce = incrementNonce(bytesOf(vectorNonce));

		expect(open(sharedKey(bytesOf(alicePublic), bobPrivate), otherNonce, bytesOf(expectedBox))).toBeUndefined();
	});

	it("increments a nonce as a little-endian integer", () => {
		const carrying = new Uint8Array(24);

		carrying[0] = 0xff;
		carrying[1] = 0xff;

		const incremented = incrementNonce(carrying);

		expect(hexOf(incremented)).toBe(`000001${"00".repeat(21)}`);
		expect(hexOf(carrying)).toBe(`ffff${"00".repeat(22)}`);
	});

	it("wraps an all-ones nonce to zero", () => {
		expect(hexOf(incrementNonce(new Uint8Array(24).fill(0xff)))).toBe("00".repeat(24));
	});

	it("generates distinct key pairs with a full-length public key", () => {
		const first = generateKeyPair();
		const second = generateKeyPair();

		expect(first.publicKey.length).toBe(keyLength);
		expect(second.publicKey.length).toBe(keyLength);
		expect(hexOf(first.publicKey)).not.toBe(hexOf(second.publicKey));
	});

	it("generates a distinct twenty-four byte nonce", () => {
		expect(randomNonce().length).toBe(24);
		expect(hexOf(randomNonce())).not.toBe(hexOf(randomNonce()));
	});
});
