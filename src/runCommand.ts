import { constants as osConstants } from "node:os";
import { CredactError, type Invocation } from "./parseArguments";
import { redactBuffer } from "./redactBuffer";
import { spawn } from "./spawn";
import { terminateChild } from "./terminateChild";
import type { ResolvedSecret } from "./resolveSecrets";
import type { ChildProcess } from "node:child_process";

export interface RunOptions {
	readonly invocation: Invocation;
	readonly secrets: Array<ResolvedSecret>;
}

const outputLimitBytes = 64 * 1024 * 1024;
const forwardedSignals: Array<NodeJS.Signals> = ["SIGINT", "SIGTERM", "SIGHUP"];

interface ChildResult {
	readonly code: number | null;
	readonly signal: NodeJS.Signals | null;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

const mapSpawnError = (failure: unknown): CredactError => {
	const code = isRecord(failure) ? failure.code : undefined;

	if (code === "ENOENT") {
		return new CredactError("spawn", 127, "credact: command was not found");
	}

	if (code === "EACCES") {
		return new CredactError("spawn", 126, "credact: command is not executable");
	}

	return new CredactError("spawn", 1, "credact: command could not start");
};

const createEnvironment = (secrets: Array<ResolvedSecret>): NodeJS.ProcessEnv => {
	const names = new Set(secrets.map((secret) => secret.name.toLowerCase()));
	const environment: NodeJS.ProcessEnv = {};

	for (const [name, value] of Object.entries(process.env)) {
		if (!names.has(name.toLowerCase())) {
			environment[name] = value;
		}
	}

	for (const secret of secrets) {
		environment[secret.name] = secret.value;
	}

	return environment;
};

const waitForChild = async (child: ChildProcess): Promise<ChildResult> =>
	new Promise<ChildResult>((resolve, reject) => {
		let settled = false;

		const finish = (action: () => void): void => {
			if (settled) {
				return;
			}

			settled = true;
			action();
		};

		child.on("error", (failure) => finish(() => reject(mapSpawnError(failure))));
		child.on("close", (code, signal) => finish(() => resolve({ code, signal })));
	});

const mapChildResult = (result: ChildResult): number => {
	if (result.code !== null) {
		return result.code;
	}

	if (result.signal === null) {
		return 1;
	}

	const signalNumber = osConstants.signals[result.signal];

	return 128 + signalNumber;
};

const writeBuffer = async (stream: NodeJS.WriteStream, output: Buffer): Promise<void> => {
	if (output.length === 0) {
		return;
	}

	await new Promise<void>((resolve, reject) => {
		stream.write(output, (writeFailure) => {
			if (writeFailure === null || writeFailure === undefined) {
				resolve();

				return;
			}

			reject(writeFailure);
		});
	});
};

export const runCommand = async ({ invocation, secrets }: RunOptions): Promise<number> => {
	const child = spawn(invocation.command, invocation.commandArguments, {
		env: createEnvironment(secrets),
		shell: false,
		stdio: invocation.scanOutput ? ["inherit", "pipe", "pipe"] : "inherit",
		windowsHide: false,
	});
	const signalHandlers = new Map<NodeJS.Signals, () => void>();
	let childClosed = false;

	child.once("close", () => {
		childClosed = true;
	});

	for (const signal of forwardedSignals) {
		const handler = (): void => {
			if (!childClosed) {
				child.kill(signal);
			}
		};

		signalHandlers.set(signal, handler);
		process.on(signal, handler);
	}

	try {
		if (!invocation.scanOutput) {
			return mapChildResult(await waitForChild(child));
		}

		if (child.stdout === null || child.stderr === null) {
			child.kill();

			throw new CredactError("output", 1, "credact: command output streams were unavailable");
		}

		const stdoutChunks: Array<Buffer> = [];
		const stderrChunks: Array<Buffer> = [];
		let capturedBytes = 0;
		let outputFailure: CredactError | undefined;
		let terminationOutcome: Promise<Error | undefined> | undefined;

		const terminateForOutput = (failure: CredactError): void => {
			if (outputFailure !== undefined) {
				return;
			}

			outputFailure = failure;
			stdoutChunks.length = 0;
			stderrChunks.length = 0;
			terminationOutcome = terminateChild(child, [child.stdout, child.stderr]).then(
				() => undefined,
				(cause: unknown) => (cause instanceof Error ? cause : new Error("child termination failed")),
			);
		};

		const capture = (chunks: Array<Buffer>, chunk: Buffer | string): void => {
			if (outputFailure !== undefined) {
				return;
			}

			const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);

			capturedBytes += bytes.length;

			if (capturedBytes > outputLimitBytes) {
				terminateForOutput(new CredactError("output-limit", 1, "credact: command output exceeded 64 MiB"));

				return;
			}

			chunks.push(bytes);
		};

		child.stdout.on("data", (chunk: Buffer | string) => capture(stdoutChunks, chunk));
		child.stderr.on("data", (chunk: Buffer | string) => capture(stderrChunks, chunk));
		child.stdout.on("error", () =>
			terminateForOutput(new CredactError("output", 1, "credact: failed to read command stdout")),
		);
		child.stderr.on("error", () =>
			terminateForOutput(new CredactError("output", 1, "credact: failed to read command stderr")),
		);

		const result = await waitForChild(child);
		const terminationError = await terminationOutcome;

		if (terminationError !== undefined) {
			throw new CredactError("output", 1, "credact: command could not be terminated", {
				cause: terminationError,
			});
		}

		if (outputFailure !== undefined) {
			throw outputFailure;
		}

		const values = secrets.map((secret) => secret.value);
		let stdout: Buffer;
		let stderr: Buffer;

		try {
			stdout = redactBuffer(Buffer.concat(stdoutChunks), values);
			stderr = redactBuffer(Buffer.concat(stderrChunks), values);
		} catch (cause) {
			throw new CredactError("output", 1, "credact: command output could not be redacted", { cause });
		}

		try {
			await Promise.all([writeBuffer(process.stdout, stdout), writeBuffer(process.stderr, stderr)]);
		} catch (cause) {
			throw new CredactError("output", 1, "credact: command output could not be written", { cause });
		}

		return mapChildResult(result);
	} finally {
		for (const [signal, handler] of signalHandlers) {
			process.removeListener(signal, handler);
		}
	}
};
