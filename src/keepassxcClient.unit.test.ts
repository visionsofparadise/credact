import { randomUUID } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { generateKeyPair, incrementNonce, open, seal, sharedKey } from "./keepassxcBox";
import {
	createLookupSession,
	KeePassXcError,
	resolveSocketPath,
	splitJsonValues,
	type ClientOptions,
} from "./keepassxcClient";

const base64Of = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");

const bytesOf = (encoded: string): Uint8Array => new Uint8Array(Buffer.from(encoded, "base64"));

const utf8Of = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "utf8"));

const delay = async (milliseconds: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, milliseconds));

interface ScriptedReply {
	readonly error?: number;
	readonly body?: Record<string, unknown>;
	readonly broadcastBefore?: boolean;
	readonly splitWrites?: boolean;
	readonly wrongNonce?: boolean;
	readonly wrongKey?: boolean;
	readonly silent?: boolean;
	readonly rawText?: string;
	readonly floodBytes?: number;
	readonly wrongInnerNonce?: boolean;
	readonly delayMilliseconds?: number;
}

interface FakeOptions {
	readonly hostPublicKeyBytes?: number;
}

type Script = (action: string, inner: Record<string, unknown>, seen: number) => ScriptedReply;

interface Fake {
	readonly socketPath: string;
	readonly actions: Array<string>;
	readonly inners: Map<string, Record<string, unknown>>;
	readonly envelopes: Map<string, Record<string, unknown>>;
	readonly sent: Array<Record<string, unknown>>;
	readonly connectionCount: () => number;
	readonly chunkCount: () => number;
	readonly malformedChunkCount: () => number;
	readonly connectionsClosed: () => number;
}

const servers: Array<Server> = [];
const directories: Array<string> = [];

afterEach(async () => {
	for (const server of servers.splice(0)) {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}

	for (const directory of directories.splice(0)) {
		await rm(directory, { recursive: true, force: true });
	}
});

const createDirectory = async (): Promise<string> => {
	const directory = await mkdtemp(join(tmpdir(), "credact-client-"));

	directories.push(directory);

	return directory;
};

const startFake = async (script: Script, fakeOptions: FakeOptions = {}): Promise<Fake> => {
	const socketPath =
		process.platform === "win32"
			? `\\\\.\\pipe\\credact-test-${randomUUID()}`
			: join(tmpdir(), `credact-test-${randomUUID()}.sock`);
	const actions: Array<string> = [];
	const inners = new Map<string, Record<string, unknown>>();
	const envelopes = new Map<string, Record<string, unknown>>();
	const sent: Array<Record<string, unknown>> = [];
	const counts = new Map<string, number>();
	let connections = 0;
	let closed = 0;
	let chunks = 0;
	let malformedChunks = 0;

	const server = createServer((socket: Socket) => {
		connections += 1;

		const pair = generateKeyPair();
		let key: Uint8Array = new Uint8Array(32);

		socket.on("close", () => {
			closed += 1;
		});
		socket.on("error", () => undefined);
		socket.on("data", (chunk: Buffer) => {
			chunks += 1;

			let parsed: unknown;

			try {
				parsed = JSON.parse(chunk.toString("utf8")) as unknown;
			} catch {
				malformedChunks += 1;

				return;
			}

			if (typeof parsed !== "object" || parsed === null) {
				malformedChunks += 1;

				return;
			}

			const outer = parsed as Record<string, unknown>;
			const action = String(outer.action);
			const seen = counts.get(action) ?? 0;

			counts.set(action, seen + 1);
			actions.push(action);
			envelopes.set(action, outer);
			sent.push(outer);

			if (action === "change-public-keys") {
				key = sharedKey(bytesOf(String(outer.publicKey)), pair.privateKey);
				socket.write(
					JSON.stringify({
						action,
						version: "2.7.4",
						publicKey: base64Of(
							fakeOptions.hostPublicKeyBytes === undefined
								? pair.publicKey
								: pair.publicKey.subarray(0, fakeOptions.hostPublicKeyBytes),
						),
						success: "true",
						nonce: String(outer.nonce),
					}),
				);

				return;
			}

			const requestNonce = bytesOf(String(outer.nonce));
			const opened = open(key, requestNonce, bytesOf(String(outer.message)));
			const inner =
				opened === undefined ? {} : (JSON.parse(Buffer.from(opened).toString("utf8")) as Record<string, unknown>);

			inners.set(action, inner);

			void sendReply(socket, key, action, requestNonce, script(action, inner, seen));
		});
	});

	servers.push(server);

	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(socketPath, resolve);
	});

	return {
		socketPath,
		actions,
		inners,
		envelopes,
		sent,
		connectionCount: () => connections,
		chunkCount: () => chunks,
		malformedChunkCount: () => malformedChunks,
		connectionsClosed: () => closed,
	};
};

const sendReply = async (
	socket: Socket,
	key: Uint8Array,
	action: string,
	requestNonce: Uint8Array,
	scripted: ScriptedReply,
): Promise<void> => {
	if (scripted.silent === true) {
		return;
	}

	if (scripted.floodBytes !== undefined) {
		socket.write("{".repeat(scripted.floodBytes));

		return;
	}

	if (scripted.rawText !== undefined) {
		socket.write(scripted.rawText);

		return;
	}

	if (scripted.error !== undefined) {
		socket.write(JSON.stringify({ action, errorCode: String(scripted.error), error: `scripted ${scripted.error}` }));

		return;
	}

	if (scripted.delayMilliseconds !== undefined) {
		await delay(scripted.delayMilliseconds);
	}

	const replyNonce = incrementNonce(requestNonce);
	const sealKey = scripted.wrongKey === true ? new Uint8Array(32).fill(7) : key;
	const innerReply = {
		action,
		nonce: base64Of(scripted.wrongInnerNonce === true ? requestNonce : replyNonce),
		success: "true",
		...scripted.body,
	};
	const payload = JSON.stringify({
		action,
		message: base64Of(seal(sealKey, replyNonce, utf8Of(JSON.stringify(innerReply)))),
		nonce: base64Of(scripted.wrongNonce === true ? requestNonce : replyNonce),
	});
	const text =
		scripted.broadcastBefore === true ? `${JSON.stringify({ action: "database-unlocked" })}${payload}` : payload;

	if (scripted.splitWrites === true) {
		const half = Math.floor(text.length / 2);

		socket.write(text.slice(0, half));
		await delay(20);
		socket.write(text.slice(half));

		return;
	}

	socket.write(text);
};

const storedIdKey = base64Of(generateKeyPair().publicKey);

const writeStoredRecord = async (directory: string, id = "credact"): Promise<string> => {
	const recordPath = join(directory, ".credact", "keepassxc-association.json");

	await mkdir(join(directory, ".credact"), { recursive: true });
	await writeFile(recordPath, `${JSON.stringify({ id, idKey: storedIdKey })}\n`);

	return recordPath;
};

const scriptedEntries = [{ login: "synthetic-login", password: "synthetic-password", stringFields: [] }];

const associated: Script = (action) => {
	if (action === "get-logins") {
		return { body: { count: 1, entries: scriptedEntries } };
	}

	return {};
};

const lookupOnce = async (reference: string, options: ClientOptions): Promise<ReadonlyArray<unknown>> => {
	const session = createLookupSession(options);

	try {
		return await session.lookup(reference);
	} finally {
		session.close();
	}
};

const waitForClose = async (fake: Fake): Promise<number> => {
	for (let attempt = 0; attempt < 100 && fake.connectionsClosed() === 0; attempt += 1) {
		await delay(10);
	}

	return fake.connectionsClosed();
};

describe("keepassxc client", () => {
	it("derives the socket path per platform", () => {
		const username = userInfo().username;

		expect(resolveSocketPath({ KEEPASSXC_BROWSER_SOCKET_PATH: "//./pipe/custom" }, "win32")).toBe("//./pipe/custom");
		expect(resolveSocketPath({ KEEPASSXC_BROWSER_SOCKET_PATH: "", USERNAME: "someone" }, "win32")).toBe(
			`\\\\.\\pipe\\org.keepassxc.KeePassXC.BrowserServer_someone`,
		);
		expect(resolveSocketPath({}, "win32")).toBe(`\\\\.\\pipe\\org.keepassxc.KeePassXC.BrowserServer_${username}`);
		expect(resolveSocketPath({}, "darwin")).toBe(join(tmpdir(), "org.keepassxc.KeePassXC.BrowserServer"));
		expect(resolveSocketPath({}, "linux")).toBe(
			join(tmpdir(), `runtime-${username}`, "org.keepassxc.KeePassXC.BrowserServer"),
		);
	});

	it("prefers the container socket on linux when it exists", async () => {
		const directory = await createDirectory();
		const containerDirectory = join(directory, "app", "org.keepassxc.KeePassXC");

		expect(resolveSocketPath({ XDG_RUNTIME_DIR: directory }, "linux")).toBe(
			join(directory, "org.keepassxc.KeePassXC.BrowserServer"),
		);

		await mkdir(containerDirectory, { recursive: true });
		await writeFile(join(containerDirectory, "org.keepassxc.KeePassXC.BrowserServer"), "");

		expect(resolveSocketPath({ XDG_RUNTIME_DIR: directory }, "linux")).toBe(
			join(containerDirectory, "org.keepassxc.KeePassXC.BrowserServer"),
		);
	});

	it("rejects an association record whose idKey is the wrong length", async () => {
		const directory = await createDirectory();
		const recordPath = join(directory, ".credact", "keepassxc-association.json");

		await mkdir(join(directory, ".credact"), { recursive: true });
		await writeFile(recordPath, JSON.stringify({ id: "credact", idKey: base64Of(new Uint8Array(31).fill(3)) }));

		const fake = await startFake(associated);

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow(`keepassxc association record at ${recordPath} is malformed`);
	});

	it("rejects a handshake whose host public key is the wrong length", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake(associated, { hostPublicKeyBytes: 16 });

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow("keepassxc reply was malformed");
	});

	it("rejects a reply whose inner nonce differs from its outer nonce", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action, inner, seen) =>
			action === "get-databasehash" ? { wrongInnerNonce: true } : associated(action, inner, seen),
		);

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow("keepassxc reply was malformed");
	});

	it("renews the deadline for each lookup rather than spending one across the session", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action, _inner, seen) => {
			if (action === "get-logins") {
				return { body: { entries: scriptedEntries }, delayMilliseconds: seen === 0 ? 0 : 250 };
			}

			return {};
		});
		const session = createLookupSession({ socketPath: fake.socketPath, recordPath, deadlineMilliseconds: 400 });

		try {
			await session.lookup("keepassxc://synthetic/password");
			await delay(250);

			await expect(session.lookup("keepassxc://other/password")).resolves.toEqual(scriptedEntries);
		} finally {
			session.close();
		}
	});

	it("runs the sequence and returns the entries untouched", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake(associated);
		const entries = await lookupOnce("keepassxc://synthetic/password", {
			socketPath: fake.socketPath,
			recordPath,
			deadlineMilliseconds: 2_000,
		});

		expect(fake.actions).toEqual(["change-public-keys", "get-databasehash", "test-associate", "get-logins"]);
		expect(fake.inners.get("get-logins")).toEqual({
			action: "get-logins",
			url: "keepassxc://synthetic/password",
			keys: [{ id: "credact", key: storedIdKey }],
		});
		expect(entries).toEqual(scriptedEntries);
		expect(await waitForClose(fake)).toBe(1);
	});

	it("reuses one connection, handshake, and association across references", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake(associated);
		const session = createLookupSession({ socketPath: fake.socketPath, recordPath, deadlineMilliseconds: 2_000 });

		try {
			await session.lookup("keepassxc://synthetic/password");
			await session.lookup("keepassxc://other/password");
		} finally {
			session.close();
		}

		expect(fake.actions).toEqual([
			"change-public-keys",
			"get-databasehash",
			"test-associate",
			"get-logins",
			"get-logins",
		]);
		expect(fake.connectionCount()).toBe(1);
		expect(fake.inners.get("get-logins")?.url).toBe("keepassxc://other/password");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("writes each request as one raw chunk that parses whole", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake(associated);

		await lookupOnce("keepassxc://synthetic/password", {
			socketPath: fake.socketPath,
			recordPath,
			deadlineMilliseconds: 2_000,
		});

		expect(fake.chunkCount()).toBe(4);
		expect(fake.malformedChunkCount()).toBe(0);
	});

	it("carries a constant clientID and triggers unlock only on the poll", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake(associated);

		await lookupOnce("keepassxc://synthetic/password", {
			socketPath: fake.socketPath,
			recordPath,
			deadlineMilliseconds: 2_000,
		});

		const clientIds = [...fake.envelopes.values()].map((envelope) => envelope.clientID);

		expect(clientIds).toHaveLength(4);
		expect(new Set(clientIds).size).toBe(1);
		expect(typeof clientIds[0]).toBe("string");
		expect(bytesOf(String(clientIds[0])).length).toBe(24);
		expect(fake.envelopes.get("get-databasehash")?.triggerUnlock).toBe("true");
		expect(fake.envelopes.get("test-associate")?.triggerUnlock).toBeUndefined();
		expect(fake.envelopes.get("get-logins")?.triggerUnlock).toBeUndefined();
		expect(fake.envelopes.get("change-public-keys")?.triggerUnlock).toBeUndefined();
	});

	it("associates on first use and stores the id with the idKey", async () => {
		const directory = await createDirectory();
		const recordPath = join(directory, ".credact", "keepassxc-association.json");
		const fake = await startFake((action) => {
			if (action === "associate") {
				return { body: { id: "planner" } };
			}

			if (action === "get-logins") {
				return { body: { entries: scriptedEntries } };
			}

			return {};
		});

		await lookupOnce("keepassxc://synthetic/password", {
			socketPath: fake.socketPath,
			recordPath,
			deadlineMilliseconds: 2_000,
		});

		expect(fake.actions).toEqual(["change-public-keys", "get-databasehash", "associate", "get-logins"]);

		const sentIdKey = fake.inners.get("associate")?.idKey;
		const stored = JSON.parse(await readFile(recordPath, "utf8")) as Record<string, unknown>;

		expect(stored).toEqual({ id: "planner", idKey: sentIdKey });
		expect(bytesOf(String(sentIdKey)).length).toBe(32);

		if (process.platform !== "win32") {
			expect((await stat(recordPath)).mode & 0o777).toBe(0o600);
			expect((await stat(join(directory, ".credact"))).mode & 0o777).toBe(0o700);
		}
	});

	it("polls until the database is unlocked", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action, _inner, seen) => {
			if (action === "get-databasehash" && seen < 2) {
				return { error: 1 };
			}

			if (action === "get-logins") {
				return { body: { entries: scriptedEntries } };
			}

			return {};
		});
		const entries = await lookupOnce("keepassxc://synthetic/password", {
			socketPath: fake.socketPath,
			recordPath,
			deadlineMilliseconds: 2_000,
			unlockIntervalMilliseconds: 10,
		});

		expect(fake.actions.filter((action) => action === "get-databasehash").length).toBe(3);
		expect(entries).toEqual(scriptedEntries);
	});

	it("triggers the unlock prompt once rather than on every poll", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action, _inner, seen) => {
			if (action === "get-databasehash" && seen < 2) {
				return { error: 1 };
			}

			if (action === "get-logins") {
				return { body: { entries: scriptedEntries } };
			}

			return {};
		});

		await lookupOnce("keepassxc://synthetic/password", {
			socketPath: fake.socketPath,
			recordPath,
			deadlineMilliseconds: 2_000,
			unlockIntervalMilliseconds: 10,
		});

		const polls = fake.sent.filter((envelope) => envelope.action === "get-databasehash");

		expect(polls).toHaveLength(3);
		expect(polls[0]?.triggerUnlock).toBe("true");
		expect(polls.slice(1).map((envelope) => envelope.triggerUnlock)).toEqual([undefined, undefined]);
	});

	it("fails closed when the database never unlocks", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => (action === "get-databasehash" ? { error: 1 } : {}));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 100,
				unlockIntervalMilliseconds: 10,
			}),
		).rejects.toThrow("keepassxc database stayed locked");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("reads a reply that shares a chunk with a broadcast", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => {
			if (action === "get-databasehash") {
				return { broadcastBefore: true };
			}

			if (action === "get-logins") {
				return { body: { entries: scriptedEntries }, splitWrites: true };
			}

			return {};
		});
		const entries = await lookupOnce("keepassxc://synthetic/password", {
			socketPath: fake.socketPath,
			recordPath,
			deadlineMilliseconds: 2_000,
		});

		expect(entries).toEqual(scriptedEntries);
	});

	it("splits complete top-level values and keeps the incomplete tail", () => {
		const complete = splitJsonValues(Buffer.from('{"a":"}"}{"b":1}', "utf8"));

		expect(complete.values).toEqual([{ a: "}" }, { b: 1 }]);
		expect(complete.rest.length).toBe(0);

		const partial = splitJsonValues(Buffer.from('{"a":', "utf8"));

		expect(partial.values).toEqual([]);
		expect(partial.rest.toString("utf8")).toBe('{"a":');
	});

	it("names the record path when the association is rejected", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => (action === "test-associate" ? { error: 8 } : {}));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow(`keepassxc association was rejected; delete ${recordPath} to re-associate`);
		expect(await waitForClose(fake)).toBe(1);
	});

	it("reports a denied association", async () => {
		const directory = await createDirectory();
		const recordPath = join(directory, ".credact", "keepassxc-association.json");
		const fake = await startFake((action) => (action === "associate" ? { error: 6 } : {}));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow("keepassxc association was denied");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("reports no entry when the lookup matches nothing", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => (action === "get-logins" ? { error: 15 } : {}));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow("keepassxc found no entry, or access to it was denied");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("reports denied access when the entry list comes back empty", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => (action === "get-logins" ? { body: { entries: [] } } : {}));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow("keepassxc access to the matching entries was denied");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("rejects a malformed association record", async () => {
		const directory = await createDirectory();
		const recordPath = join(directory, ".credact", "keepassxc-association.json");

		await mkdir(join(directory, ".credact"), { recursive: true });
		await writeFile(recordPath, JSON.stringify({ id: 1 }));

		const fake = await startFake(associated);

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow(`keepassxc association record at ${recordPath} is malformed`);
		expect(await waitForClose(fake)).toBe(1);
	});

	it("rejects a reply whose outer nonce was not incremented", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => (action === "get-databasehash" ? { wrongNonce: true } : {}));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow("keepassxc nonce mismatch");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("rejects a reply sealed under a different key", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => (action === "get-databasehash" ? { wrongKey: true } : {}));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 2_000,
			}),
		).rejects.toThrow("keepassxc could not decrypt reply");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("fails closed when an incomplete reply exceeds the buffer cap", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => (action === "test-associate" ? { floodBytes: 1024 * 1024 + 1 } : {}));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 5_000,
			}),
		).rejects.toThrow("keepassxc reply was malformed");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("times out when the reply never parses", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => (action === "get-databasehash" ? {} : { rawText: "not-json" }));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 100,
			}),
		).rejects.toThrow("keepassxc timed out");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("times out when the server never replies", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const fake = await startFake((action) => (action === "get-databasehash" ? {} : { silent: true }));

		await expect(
			lookupOnce("keepassxc://synthetic/password", {
				socketPath: fake.socketPath,
				recordPath,
				deadlineMilliseconds: 100,
			}),
		).rejects.toThrow("keepassxc timed out");
		expect(await waitForClose(fake)).toBe(1);
	});

	it("reports an unavailable socket when nothing is listening", async () => {
		const directory = await createDirectory();
		const recordPath = await writeStoredRecord(directory);
		const socketPath =
			process.platform === "win32"
				? `\\\\.\\pipe\\credact-absent-${randomUUID()}`
				: join(directory, `absent-${randomUUID()}.sock`);
		const failure = await lookupOnce("keepassxc://synthetic/password", {
			socketPath,
			recordPath,
			deadlineMilliseconds: 2_000,
		}).catch((cause: unknown) => cause);

		expect(failure).toBeInstanceOf(KeePassXcError);
		expect((failure as KeePassXcError).message).toBe(`keepassxc socket unavailable at ${socketPath}`);
		expect((failure as KeePassXcError).errorCode).toBeUndefined();
	});
});
