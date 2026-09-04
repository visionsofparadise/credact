#!/usr/bin/env node
import { CredactError, parseArguments } from "./parseArguments";
import { redactBuffer } from "./redactBuffer";
import { resolveSecrets } from "./resolveSecrets";
import { runCommand } from "./runCommand";

const usage = "Usage: credact [--no-output-scan] SOURCE [...] -- COMMAND [ARG ...]";
const help = `${usage}

SOURCE is NAME (read from the environment) or NAME=keepassxc://entry/field.
Resolved values and documented common representations are removed from complete stdout and stderr before release.

  --no-output-scan  Inherit the terminal directly for trusted interactive commands.
  --help            Show this help when supplied as the only argument.
`;

const writeBuffer = async (stream: NodeJS.WriteStream, output: Buffer): Promise<void> => {
	await new Promise<void>((resolveWrite, rejectWrite) => {
		stream.write(output, (writeFailure) => {
			if (writeFailure === null || writeFailure === undefined) {
				resolveWrite();

				return;
			}

			rejectWrite(writeFailure);
		});
	});
};

const writeDiagnostic = async (message: string, values: Array<string>, includeUsage: boolean): Promise<void> => {
	const body = includeUsage ? `${message}\n${usage}\n` : `${message}\n`;

	await writeBuffer(process.stderr, redactBuffer(Buffer.from(body), values));
};

const writeDiagnosticSafely = async (message: string, values: Array<string>, includeUsage: boolean): Promise<void> => {
	try {
		await writeDiagnostic(message, values, includeUsage);
	} catch {
		return;
	}
};

const main = async (argumentValues: Array<string>): Promise<number> => {
	let values: Array<string> = [];

	try {
		const parseResult = parseArguments(argumentValues);

		if (parseResult.kind === "help") {
			await writeBuffer(process.stdout, Buffer.from(help));

			return 0;
		}

		const outcome = await resolveSecrets(parseResult.invocation.sources);

		values = outcome.secrets.map((secret) => secret.value);

		if (outcome.kind === "failure") {
			await writeDiagnosticSafely(outcome.error.message, values, false);

			return outcome.error.exitCode;
		}

		return await runCommand({ invocation: parseResult.invocation, secrets: outcome.secrets });
	} catch (failure) {
		if (failure instanceof CredactError) {
			await writeDiagnosticSafely(failure.message, values, failure.kind === "usage");

			return failure.exitCode;
		}

		await writeDiagnosticSafely("credact: unexpected failure", values, false);

		return 1;
	}
};

process.exitCode = await main(process.argv.slice(2));
