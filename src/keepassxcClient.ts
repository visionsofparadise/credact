import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { homedir, tmpdir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { isRecord, isUnknownArray } from "./jsonGuards";
import { generateKeyPair, incrementNonce, keyLength, open, randomNonce, seal, sharedKey } from "./keepassxcBox";

const socketName = "org.keepassxc.KeePassXC.BrowserServer";
const recordFileName = "keepassxc-association.json";
const recordDirectoryName = ".credact";
const defaultDeadlineMilliseconds = 35_000;
const defaultUnlockIntervalMilliseconds = 1_500;
const databaseLockedCode = 1;
const associationDeniedCode = 6;
const associationRejectedCode = 8;
const noLoginsCode = 15;
const maximumPendingBytes = 1024 * 1024;

const malformedReplyClass = "keepassxc reply was malformed";
const timedOutClass = "keepassxc timed out";
const databaseLockedClass = "keepassxc database stayed locked";
const nonceMismatchClass = "keepassxc nonce mismatch";
const decryptionClass = "keepassxc could not decrypt reply";
const associationDeniedClass = "keepassxc association was denied";
const accessDeniedClass = "keepassxc access to the matching entries was denied";
const noEntryOrDeniedClass = "keepassxc found no entry, or access to it was denied";

export class KeePassXcError extends Error {
	readonly failureClass: string;
	readonly errorCode: number | undefined;

	constructor(failureClass: string, errorCode?: number) {
		super(failureClass);
		this.failureClass = failureClass;
		this.errorCode = errorCode;
	}
}

export interface ClientOptions {
	readonly socketPath?: string;
	readonly recordPath?: string;
	readonly deadlineMilliseconds?: number;
	readonly unlockIntervalMilliseconds?: number;
	readonly environment?: NodeJS.ProcessEnv;
}

const base64Of = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");

const bytesOf = (encoded: string): Uint8Array => new Uint8Array(Buffer.from(encoded, "base64"));

export const resolveSocketPath = (
	environment: NodeJS.ProcessEnv = process.env,
	platform: NodeJS.Platform = process.platform,
): string => {
	const override = environment.KEEPASSXC_BROWSER_SOCKET_PATH;

	if (override !== undefined && override.length > 0) {
		return override;
	}

	if (platform === "win32") {
		return `\\\\.\\pipe\\${socketName}_${environment.USERNAME ?? userInfo().username}`;
	}

	if (platform === "linux") {
		const runtimeDirectory = environment.XDG_RUNTIME_DIR ?? join(tmpdir(), `runtime-${userInfo().username}`);
		const containerPath = join(runtimeDirectory, "app", "org.keepassxc.KeePassXC", socketName);

		return existsSync(containerPath) ? containerPath : join(runtimeDirectory, socketName);
	}

	return join(tmpdir(), socketName);
};

interface AssociationRecord {
	readonly id: string;
	readonly idKey: Uint8Array;
}

const readRecord = async (recordPath: string): Promise<AssociationRecord | undefined> => {
	const malformed = new KeePassXcError(`keepassxc association record at ${recordPath} is malformed`);
	let content: string;

	try {
		content = await readFile(recordPath, "utf8");
	} catch (cause) {
		if (isRecord(cause) && cause.code === "ENOENT") {
			return undefined;
		}

		throw malformed;
	}

	let parsed: unknown;

	try {
		parsed = JSON.parse(content) as unknown;
	} catch {
		throw malformed;
	}

	if (
		!isRecord(parsed) ||
		typeof parsed.id !== "string" ||
		parsed.id.length === 0 ||
		typeof parsed.idKey !== "string"
	) {
		throw malformed;
	}

	const idKey = bytesOf(parsed.idKey);

	if (idKey.length !== keyLength) {
		throw malformed;
	}

	return { id: parsed.id, idKey };
};

const writeRecord = async (recordPath: string, record: AssociationRecord): Promise<void> => {
	await mkdir(dirname(recordPath), { recursive: true, mode: 0o700 });
	await writeFile(recordPath, `${JSON.stringify({ id: record.id, idKey: base64Of(record.idKey) })}\n`, {
		mode: 0o600,
	});
};

const quote = 0x22;
const backslash = 0x5c;
const openingBrace = 0x7b;
const closingBrace = 0x7d;
const openingBracket = 0x5b;
const closingBracket = 0x5d;

export const splitJsonValues = (buffer: Buffer): { readonly values: Array<unknown>; readonly rest: Buffer } => {
	const values: Array<unknown> = [];
	let start = 0;
	let depth = 0;
	let inString = false;
	let escaped = false;

	for (let index = 0; index < buffer.length; index += 1) {
		const character = buffer[index];

		if (escaped) {
			escaped = false;
		} else if (inString) {
			if (character === backslash) {
				escaped = true;
			} else if (character === quote) {
				inString = false;
			}
		} else if (character === quote) {
			inString = true;
		} else if (character === openingBrace || character === openingBracket) {
			depth += 1;
		} else if (character === closingBrace || character === closingBracket) {
			depth -= 1;

			if (depth <= 0) {
				try {
					values.push(JSON.parse(buffer.subarray(start, index + 1).toString("utf8")) as unknown);
				} catch {
					void 0;
				}

				depth = 0;
				start = index + 1;
			}
		}
	}

	return { values, rest: buffer.subarray(start) };
};

interface Waiter {
	readonly action: string;
	readonly resolve: (reply: Record<string, unknown>) => void;
	readonly reject: (error: KeePassXcError) => void;
}

interface Sleeper {
	readonly timer: NodeJS.Timeout;
	readonly reject: (error: KeePassXcError) => void;
}

interface Session {
	readonly request: (outer: Record<string, unknown>, action: string) => Promise<Record<string, unknown>>;
	readonly sleep: (milliseconds: number) => Promise<void>;
	readonly renewDeadline: () => void;
	readonly close: () => void;
}

const connectSession = async (socketPath: string, deadlineMilliseconds: number): Promise<Session> =>
	new Promise<Session>((resolveSession, rejectSession) => {
		const socket = connect({ path: socketPath });
		const waiters: Array<Waiter> = [];
		const sleepers: Array<Sleeper> = [];
		let received: Buffer = Buffer.alloc(0);
		let settled = false;
		let failure: KeePassXcError | undefined;
		let deadline: NodeJS.Timeout;

		const fail = (error: KeePassXcError): void => {
			failure ??= error;
			clearTimeout(deadline);

			for (const sleeper of sleepers.splice(0)) {
				clearTimeout(sleeper.timer);
				sleeper.reject(failure);
			}

			for (const waiter of waiters.splice(0)) {
				waiter.reject(failure);
			}

			socket.destroy();

			if (!settled) {
				settled = true;
				rejectSession(failure);
			}
		};

		const armDeadline = (): void => {
			deadline = setTimeout(() => {
				fail(new KeePassXcError(timedOutClass));
			}, deadlineMilliseconds);
		};

		armDeadline();

		const session: Session = {
			request: async (outer, action) =>
				new Promise<Record<string, unknown>>((resolveRequest, rejectRequest) => {
					if (failure !== undefined) {
						rejectRequest(failure);

						return;
					}

					waiters.push({ action, resolve: resolveRequest, reject: rejectRequest });
					socket.write(JSON.stringify(outer));
				}),
			sleep: async (milliseconds) =>
				new Promise<void>((resolveSleep, rejectSleep) => {
					if (failure !== undefined) {
						rejectSleep(failure);

						return;
					}

					const sleeper: Sleeper = {
						timer: setTimeout(() => {
							const index = sleepers.indexOf(sleeper);

							if (index >= 0) {
								sleepers.splice(index, 1);
							}

							resolveSleep();
						}, milliseconds),
						reject: rejectSleep,
					};

					sleepers.push(sleeper);
				}),
			renewDeadline: () => {
				if (failure !== undefined) {
					return;
				}

				clearTimeout(deadline);
				armDeadline();
			},
			close: () => {
				clearTimeout(deadline);

				for (const sleeper of sleepers.splice(0)) {
					clearTimeout(sleeper.timer);
				}

				socket.destroy();
			},
		};

		socket.on("error", () => {
			fail(new KeePassXcError(`keepassxc socket unavailable at ${socketPath}`));
		});
		socket.on("close", () => {
			if (waiters.length > 0 || !settled) {
				fail(new KeePassXcError(`keepassxc socket unavailable at ${socketPath}`));
			}
		});
		socket.on("data", (chunk: Buffer) => {
			received = Buffer.concat([received, chunk]);

			const { values, rest } = splitJsonValues(received);

			received = rest;

			if (received.length > maximumPendingBytes) {
				fail(new KeePassXcError(malformedReplyClass));

				return;
			}

			for (const value of values) {
				if (!isRecord(value)) {
					continue;
				}

				const index = waiters.findIndex((waiter) => waiter.action === value.action);

				if (index < 0) {
					continue;
				}

				waiters.splice(index, 1)[0]?.resolve(value);
			}
		});
		socket.on("connect", () => {
			settled = true;
			resolveSession(session);
		});
	});

interface SessionKeys {
	readonly clientId: string;
	readonly publicKey: Uint8Array;
	readonly key: Uint8Array;
}

const handshake = async (session: Session): Promise<SessionKeys> => {
	const pair = generateKeyPair();
	const clientId = base64Of(randomNonce());
	const reply = await session.request(
		{
			action: "change-public-keys",
			publicKey: base64Of(pair.publicKey),
			nonce: base64Of(randomNonce()),
			clientID: clientId,
		},
		"change-public-keys",
	);

	if (reply.success !== "true" || typeof reply.publicKey !== "string") {
		throw new KeePassXcError(malformedReplyClass);
	}

	const hostPublicKey = bytesOf(reply.publicKey);

	if (hostPublicKey.length !== keyLength) {
		throw new KeePassXcError(malformedReplyClass);
	}

	return { clientId, publicKey: pair.publicKey, key: sharedKey(hostPublicKey, pair.privateKey) };
};

const errorOf = (reply: Record<string, unknown>): KeePassXcError => {
	const parsed = Number.parseInt(String(reply.errorCode), 10);
	const code = Number.isNaN(parsed) ? undefined : parsed;
	const description = typeof reply.error === "string" ? reply.error : "";

	return new KeePassXcError(`keepassxc error ${code ?? "unknown"}: ${description}`, code);
};

const encryptedRequest = async (
	session: Session,
	keys: SessionKeys,
	action: string,
	inner: Record<string, unknown>,
	triggerUnlock = false,
): Promise<Record<string, unknown>> => {
	const nonce = randomNonce();
	const sealed = seal(keys.key, nonce, new Uint8Array(Buffer.from(JSON.stringify({ action, ...inner }), "utf8")));
	const outer: Record<string, unknown> = {
		action,
		message: base64Of(sealed),
		nonce: base64Of(nonce),
		clientID: keys.clientId,
	};

	if (triggerUnlock) {
		outer.triggerUnlock = "true";
	}

	const reply = await session.request(outer, action);

	if (reply.errorCode !== undefined) {
		throw errorOf(reply);
	}

	const replyNonce = incrementNonce(nonce);
	const expected = base64Of(replyNonce);

	if (reply.nonce !== expected) {
		throw new KeePassXcError(nonceMismatchClass);
	}

	if (typeof reply.message !== "string") {
		throw new KeePassXcError(malformedReplyClass);
	}

	const opened = open(keys.key, replyNonce, bytesOf(reply.message));

	if (opened === undefined) {
		throw new KeePassXcError(decryptionClass);
	}

	let parsed: unknown;

	try {
		parsed = JSON.parse(Buffer.from(opened).toString("utf8")) as unknown;
	} catch {
		throw new KeePassXcError(malformedReplyClass);
	}

	if (!isRecord(parsed) || parsed.success !== "true" || parsed.nonce !== expected) {
		throw new KeePassXcError(malformedReplyClass);
	}

	return parsed;
};

const waitForOpen = async (session: Session, keys: SessionKeys, unlockIntervalMilliseconds: number): Promise<void> => {
	try {
		let triggerUnlock = true;

		for (;;) {
			try {
				await encryptedRequest(session, keys, "get-databasehash", {}, triggerUnlock);

				return;
			} catch (cause) {
				if (!(cause instanceof KeePassXcError) || cause.errorCode !== databaseLockedCode) {
					throw cause;
				}
			}

			triggerUnlock = false;

			await session.sleep(unlockIntervalMilliseconds);
		}
	} catch (cause) {
		if (cause instanceof KeePassXcError && cause.failureClass === timedOutClass) {
			throw new KeePassXcError(databaseLockedClass);
		}

		throw cause;
	}
};

const associate = async (session: Session, keys: SessionKeys, recordPath: string): Promise<AssociationRecord> => {
	const existing = await readRecord(recordPath);

	if (existing !== undefined) {
		try {
			await encryptedRequest(session, keys, "test-associate", {
				id: existing.id,
				key: base64Of(existing.idKey),
			});
		} catch (cause) {
			if (cause instanceof KeePassXcError && cause.errorCode === associationRejectedCode) {
				throw new KeePassXcError(`keepassxc association was rejected; delete ${recordPath} to re-associate`);
			}

			throw cause;
		}

		return existing;
	}

	const identity = generateKeyPair();
	let reply: Record<string, unknown>;

	try {
		reply = await encryptedRequest(session, keys, "associate", {
			key: base64Of(keys.publicKey),
			idKey: base64Of(identity.publicKey),
		});
	} catch (cause) {
		if (cause instanceof KeePassXcError && cause.errorCode === associationDeniedCode) {
			throw new KeePassXcError(associationDeniedClass);
		}

		throw cause;
	}

	if (typeof reply.id !== "string" || reply.id.length === 0) {
		throw new KeePassXcError(malformedReplyClass);
	}

	const record: AssociationRecord = { id: reply.id, idKey: identity.publicKey };

	await writeRecord(recordPath, record);

	return record;
};

interface OpenSession {
	readonly session: Session;
	readonly keys: SessionKeys;
	readonly record: AssociationRecord;
}

export interface LookupSession {
	readonly lookup: (reference: string) => Promise<ReadonlyArray<unknown>>;
	readonly close: () => void;
}

export const createLookupSession = (options: ClientOptions = {}): LookupSession => {
	const environment = options.environment ?? process.env;
	const socketPath = options.socketPath ?? resolveSocketPath(environment);
	const recordPath = options.recordPath ?? join(homedir(), recordDirectoryName, recordFileName);
	const deadlineMilliseconds = options.deadlineMilliseconds ?? defaultDeadlineMilliseconds;
	const unlockIntervalMilliseconds = options.unlockIntervalMilliseconds ?? defaultUnlockIntervalMilliseconds;
	let opening: Promise<OpenSession> | undefined;

	const start = async (): Promise<OpenSession> => {
		const session = await connectSession(socketPath, deadlineMilliseconds);

		try {
			const keys = await handshake(session);

			await waitForOpen(session, keys, unlockIntervalMilliseconds);

			return { session, keys, record: await associate(session, keys, recordPath) };
		} catch (cause) {
			session.close();

			throw cause;
		}
	};

	return {
		lookup: async (reference) => {
			opening ??= start();

			const { session, keys, record } = await opening;

			session.renewDeadline();

			let reply: Record<string, unknown>;

			try {
				reply = await encryptedRequest(session, keys, "get-logins", {
					url: reference,
					keys: [{ id: record.id, key: base64Of(record.idKey) }],
				});
			} catch (cause) {
				if (cause instanceof KeePassXcError && cause.errorCode === noLoginsCode) {
					throw new KeePassXcError(noEntryOrDeniedClass);
				}

				throw cause;
			}

			if (!isUnknownArray(reply.entries)) {
				throw new KeePassXcError(malformedReplyClass);
			}

			if (reply.entries.length === 0) {
				throw new KeePassXcError(accessDeniedClass);
			}

			return reply.entries;
		},
		close: () => {
			void opening?.then(
				({ session }) => {
					session.close();
				},
				() => undefined,
			);
		},
	};
};
