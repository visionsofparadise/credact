import { isRecord, isUnknownArray } from "./jsonGuards";
import { createLookupSession, KeePassXcError } from "./keepassxcClient";
import { CredactError, type EnvironmentSecretSource, type SecretSource } from "./parseArguments";

export type ResolvedSecret = SecretSource & { readonly value: string };

export type EntryLookup = (reference: string) => Promise<ReadonlyArray<unknown>>;

export type ResolutionOutcome =
	| { readonly kind: "success"; readonly secrets: Array<ResolvedSecret> }
	| {
			readonly kind: "failure";
			readonly secrets: Array<ResolvedSecret>;
			readonly error: CredactError;
	  };

const createResolutionError = (name: string, failureClass: string): CredactError =>
	new CredactError("resolution", 1, `credact: ${name}: ${failureClass}`);

interface ParsedEntry {
	readonly login: unknown;
	readonly password: unknown;
	readonly stringFields: Array<unknown>;
}

const parseEntry = (entries: ReadonlyArray<unknown>): ParsedEntry | undefined => {
	if (entries.length !== 1) {
		return undefined;
	}

	const entry = entries[0];

	if (!isRecord(entry) || !isUnknownArray(entry.stringFields)) {
		return undefined;
	}

	return {
		login: entry.login,
		password: entry.password,
		stringFields: entry.stringFields,
	};
};

const getFieldName = (reference: string): string | undefined => {
	try {
		const parsed = new URL(reference);
		const segment = parsed.pathname.split("/").at(-1);

		return segment === undefined || segment.length === 0 ? undefined : decodeURIComponent(segment);
	} catch {
		return undefined;
	}
};

const selectValue = (entry: ParsedEntry, fieldName: string): string | undefined => {
	if (fieldName === "username") {
		return typeof entry.login === "string" ? entry.login : undefined;
	}

	if (fieldName === "password") {
		return typeof entry.password === "string" ? entry.password : undefined;
	}

	const protectedName = `KPH: ${fieldName}`;
	const matches: Array<unknown> = [];

	for (const field of entry.stringFields) {
		if (!isRecord(field) || !Object.hasOwn(field, protectedName)) {
			continue;
		}

		matches.push(field[protectedName]);
	}

	return matches.length === 1 && typeof matches[0] === "string" ? matches[0] : undefined;
};

interface ReferenceResult {
	readonly kind: "success" | "failure";
	readonly value?: string;
	readonly failureClass?: string;
}

const resolveReference = async (reference: string, lookup: EntryLookup): Promise<ReferenceResult> => {
	let entries: ReadonlyArray<unknown>;

	try {
		entries = await lookup(reference);
	} catch (cause) {
		return {
			kind: "failure",
			failureClass: cause instanceof KeePassXcError ? cause.failureClass : "keepassxc lookup failed",
		};
	}

	const entry = parseEntry(entries);
	const fieldName = getFieldName(reference);

	if (entry === undefined) {
		return { kind: "failure", failureClass: "keepassxc reply had no single usable entry" };
	}

	if (fieldName === undefined) {
		return { kind: "failure", failureClass: "reference field was invalid" };
	}

	const value = selectValue(entry, fieldName);

	if (value === undefined) {
		return { kind: "failure", failureClass: "requested field was absent or ambiguous" };
	}

	if (value.length === 0) {
		return { kind: "failure", failureClass: "resolved value was empty" };
	}

	if (value === reference) {
		return { kind: "failure", failureClass: "keepassxc returned the unresolved reference" };
	}

	return { kind: "success", value };
};

const resolveEnvironment = (source: EnvironmentSecretSource, environment: NodeJS.ProcessEnv): ReferenceResult => {
	const foldedName = source.name.toLowerCase();
	const matches = Object.entries(environment).filter(([name]) => name.toLowerCase() === foldedName);

	if (matches.length !== 1) {
		return {
			kind: "failure",
			failureClass: matches.length === 0 ? "environment value was absent" : "environment name was ambiguous",
		};
	}

	const value = matches[0]?.[1];

	return typeof value === "string" && value.length > 0
		? { kind: "success", value }
		: { kind: "failure", failureClass: "environment value was empty" };
};

export const resolveSecrets = async (
	sources: Array<SecretSource>,
	lookup?: EntryLookup,
	environment: NodeJS.ProcessEnv = process.env,
): Promise<ResolutionOutcome> => {
	const session = createLookupSession({ environment });
	const entryLookup = lookup ?? session.lookup;
	const environmentResults = new Map<string, ReferenceResult>();
	const referenceResults = new Map<string, ReferenceResult>();

	try {
		for (const source of sources) {
			if (source.kind === "environment") {
				environmentResults.set(source.name.toLowerCase(), resolveEnvironment(source, environment));
			} else if (!referenceResults.has(source.reference)) {
				referenceResults.set(source.reference, await resolveReference(source.reference, entryLookup));
			}
		}
	} finally {
		session.close();
	}

	const secrets: Array<ResolvedSecret> = [];
	let failure: CredactError | undefined;

	for (const source of sources) {
		const result =
			source.kind === "environment"
				? environmentResults.get(source.name.toLowerCase())
				: referenceResults.get(source.reference);

		if (result?.kind === "success" && result.value !== undefined) {
			secrets.push({ ...source, value: result.value });

			continue;
		}

		failure ??= createResolutionError(source.name, result?.failureClass ?? "secret resolution failed");
	}

	return failure === undefined ? { kind: "success", secrets } : { kind: "failure", secrets, error: failure };
};
