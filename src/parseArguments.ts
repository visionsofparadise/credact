export interface EnvironmentSecretSource {
	readonly kind: "environment";
	readonly name: string;
}

export interface KeePassSecretSource {
	readonly kind: "keepassxc";
	readonly name: string;
	readonly reference: string;
}

export type SecretSource = EnvironmentSecretSource | KeePassSecretSource;

export interface Invocation {
	readonly command: string;
	readonly commandArguments: Array<string>;
	readonly scanOutput: boolean;
	readonly sources: Array<SecretSource>;
}

export type ParseResult = { readonly kind: "help" } | { readonly kind: "run"; readonly invocation: Invocation };

export type CredactErrorKind = "usage" | "resolution" | "spawn" | "output-limit" | "output";

export class CredactError extends Error {
	readonly kind: CredactErrorKind;
	readonly exitCode: 1 | 2 | 126 | 127;

	constructor(kind: CredactErrorKind, exitCode: 1 | 2 | 126 | 127, message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "CredactError";
		this.kind = kind;
		this.exitCode = exitCode;
	}
}

const environmentNamePattern = /^[A-Za-z_][A-Za-z0-9_]*$/u;

const failUsage = (message: string): never => {
	throw new CredactError("usage", 2, message);
};

const validateReference = (reference: string): void => {
	if (!reference.startsWith("keepassxc://")) {
		failUsage("assignment references must use keepassxc://");
	}

	let parsed: URL;

	try {
		parsed = new URL(reference);
	} catch {
		return failUsage("assignment reference is invalid");
	}

	if (parsed.hostname.length === 0 || reference.includes("?") || reference.includes("#")) {
		failUsage("assignment reference is invalid");
	}

	const finalSlash = reference.lastIndexOf("/");

	if (finalSlash < "keepassxc://".length || finalSlash === reference.length - 1) {
		failUsage("assignment reference must name a field");
	}
};

const parseSource = (token: string): SecretSource => {
	const equalsIndex = token.indexOf("=");

	if (equalsIndex < 0) {
		if (!environmentNamePattern.test(token)) {
			return failUsage("source has an invalid environment name");
		}

		return { kind: "environment", name: token };
	}

	if (equalsIndex === 0) {
		return failUsage("source has an invalid environment name");
	}

	const name = token.slice(0, equalsIndex);
	const reference = token.slice(equalsIndex + 1);

	if (!environmentNamePattern.test(name)) {
		failUsage("source has an invalid environment name");
	}

	validateReference(reference);

	return { kind: "keepassxc", name, reference };
};

export const parseArguments = (argumentValues: Array<string>): ParseResult => {
	if (argumentValues.length === 1 && argumentValues[0] === "--help") {
		return { kind: "help" };
	}

	const delimiterIndex = argumentValues.indexOf("--");

	if (delimiterIndex < 0) {
		return failUsage("missing mandatory -- command delimiter");
	}

	const runnerArguments = argumentValues.slice(0, delimiterIndex);
	const commandArguments = argumentValues.slice(delimiterIndex + 1);
	const command = commandArguments.shift();

	if (command === undefined || command.length === 0) {
		return failUsage("missing command after --");
	}

	let scanOutput = true;
	let sawSource = false;
	const sources: Array<SecretSource> = [];
	const names = new Set<string>();

	for (const token of runnerArguments) {
		if (token === "--no-output-scan") {
			if (sawSource || !scanOutput) {
				failUsage("--no-output-scan must appear once before sources");
			}

			scanOutput = false;

			continue;
		}

		sawSource = true;

		const source = parseSource(token);
		const foldedName = source.name.toLowerCase();

		if (names.has(foldedName)) {
			failUsage("source environment names must be unique");
		}

		names.add(foldedName);
		sources.push(source);
	}

	if (sources.length === 0) {
		return failUsage("at least one secret source is required");
	}

	return {
		kind: "run",
		invocation: {
			command,
			commandArguments,
			scanOutput,
			sources,
		},
	};
};
