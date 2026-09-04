import { describe, expect, it, vi } from "vitest";
import { KeePassXcError } from "./keepassxcClient";
import { type EnvironmentSecretSource, type KeePassSecretSource } from "./parseArguments";
import { resolveSecrets, type EntryLookup } from "./resolveSecrets";

const keepassSource = (name: string, reference: string): KeePassSecretSource => ({
	kind: "keepassxc",
	name,
	reference,
});
const environmentSource = (name: string): EnvironmentSecretSource => ({ kind: "environment", name });

const response = (entry: Record<string, unknown>): ReadonlyArray<unknown> => [
	{
		login: "synthetic-login",
		password: "synthetic-password",
		stringFields: [],
		...entry,
	},
];

describe("resolveSecrets", () => {
	it("selects username, password, and a unique protected custom field", async () => {
		const lookup: EntryLookup = async () =>
			response({
				stringFields: [{ "KPH: api key": "synthetic-api-value" }],
			});

		await expect(
			resolveSecrets(
				[
					keepassSource("LOGIN", "keepassxc://service/username"),
					keepassSource("PASSWORD", "keepassxc://service/password"),
					keepassSource("API_KEY", "keepassxc://service/api%20key"),
				],
				lookup,
			),
		).resolves.toEqual({
			kind: "success",
			secrets: [
				{ kind: "keepassxc", name: "LOGIN", reference: "keepassxc://service/username", value: "synthetic-login" },
				{
					kind: "keepassxc",
					name: "PASSWORD",
					reference: "keepassxc://service/password",
					value: "synthetic-password",
				},
				{
					kind: "keepassxc",
					name: "API_KEY",
					reference: "keepassxc://service/api%20key",
					value: "synthetic-api-value",
				},
			],
		});
	});

	it("deduplicates identical references while preserving sources", async () => {
		const lookup = vi.fn<EntryLookup>(async () => response({}));
		const reference = "keepassxc://service/password";

		const outcome = await resolveSecrets(
			[keepassSource("FIRST", reference), keepassSource("SECOND", reference)],
			lookup,
		);

		expect(lookup).toHaveBeenCalledOnce();
		expect(outcome).toEqual({
			kind: "success",
			secrets: [
				{ kind: "keepassxc", name: "FIRST", reference, value: "synthetic-password" },
				{ kind: "keepassxc", name: "SECOND", reference, value: "synthetic-password" },
			],
		});
	});

	it("attempts every distinct reference and retains successes in a failure outcome", async () => {
		const lookup = vi.fn<EntryLookup>(async (reference) => {
			if (reference.includes("failure")) {
				throw new Error("raw-helper-output synthetic-hidden-value");
			}

			return response({ password: "synthetic-success-value" });
		});

		const outcome = await resolveSecrets(
			[
				keepassSource("BROKEN", "keepassxc://failure/password"),
				keepassSource("WORKING", "keepassxc://success/password"),
			],
			lookup,
		);

		expect(lookup).toHaveBeenCalledTimes(2);
		expect(outcome.kind).toBe("failure");

		if (outcome.kind === "failure") {
			expect(outcome.secrets).toEqual([
				{
					kind: "keepassxc",
					name: "WORKING",
					reference: "keepassxc://success/password",
					value: "synthetic-success-value",
				},
			]);
			expect(outcome.error).toMatchObject({ kind: "resolution", exitCode: 1 });
			expect(outcome.error.message).toContain("BROKEN");
			expect(outcome.error.message).not.toContain("raw-helper-output");
			expect(outcome.error.message).not.toContain("synthetic-hidden-value");
			expect(outcome.error.message).not.toContain("synthetic-success-value");
		}
	});

	it("resolves environment sources without calling the lookup", async () => {
		const lookup = vi.fn<EntryLookup>(() => Promise.reject(new Error("must not be called")));

		await expect(
			resolveSecrets([environmentSource("API_TOKEN")], lookup, { api_token: "synthetic-environment-value" }),
		).resolves.toEqual({
			kind: "success",
			secrets: [{ kind: "environment", name: "API_TOKEN", value: "synthetic-environment-value" }],
		});
		expect(lookup).not.toHaveBeenCalled();
	});

	it("resolves mixed sources and retains both source kinds", async () => {
		const lookup = vi.fn<EntryLookup>(async () => response({}));

		await expect(
			resolveSecrets(
				[environmentSource("REMOTE_TOKEN"), keepassSource("LOCAL_TOKEN", "keepassxc://service/password")],
				lookup,
				{ REMOTE_TOKEN: "synthetic-remote-value" },
			),
		).resolves.toEqual({
			kind: "success",
			secrets: [
				{ kind: "environment", name: "REMOTE_TOKEN", value: "synthetic-remote-value" },
				{
					kind: "keepassxc",
					name: "LOCAL_TOKEN",
					reference: "keepassxc://service/password",
					value: "synthetic-password",
				},
			],
		});
		expect(lookup).toHaveBeenCalledOnce();
	});

	it.each([
		[{}, "absent"],
		[{ API_TOKEN: "" }, "empty"],
		[{ API_TOKEN: "one", api_token: "two" }, "ambiguous"],
	] as const)("fails closed when an environment value is %s", async (environment, failureClass) => {
		const outcome = await resolveSecrets([environmentSource("API_TOKEN")], undefined, environment);

		expect(outcome).toMatchObject({ kind: "failure", secrets: [], error: { kind: "resolution", exitCode: 1 } });

		if (outcome.kind === "failure") {
			expect(outcome.error.message).toContain(failureClass);
		}
	});

	it.each([
		[[]],
		[[{ stringFields: [] }, { stringFields: [] }]],
		[[{ login: "synthetic-login", password: "synthetic-password" }]],
	] as Array<[ReadonlyArray<unknown>]>)("fails closed for a reply with no single usable entry %#", async (entries) => {
		const outcome = await resolveSecrets(
			[keepassSource("TOKEN", "keepassxc://service/password")],
			async () => entries,
		);

		expect(outcome).toMatchObject({ kind: "failure", error: { kind: "resolution", exitCode: 1 } });

		if (outcome.kind === "failure") {
			expect(outcome.error.message).toContain("keepassxc reply had no single usable entry");
		}
	});

	it.each([
		["keepassxc://service/missing", response({})],
		[
			"keepassxc://service/duplicate",
			response({ stringFields: [{ "KPH: duplicate": "one" }, { "KPH: duplicate": "two" }] }),
		],
		[
			"keepassxc://service/duplicate",
			response({ stringFields: [{ "KPH: duplicate": "one" }, { "KPH: duplicate": 2 }] }),
		],
		["keepassxc://service/custom", response({ stringFields: [{ "KPH: custom": false }] })],
		["keepassxc://service/password", response({ password: "" })],
		["keepassxc://service/password", response({ password: "keepassxc://service/password" })],
	])("fails closed for unusable field %#", async (reference, entries) => {
		const outcome = await resolveSecrets([keepassSource("TOKEN", reference)], async () => entries);

		expect(outcome).toMatchObject({ kind: "failure", secrets: [], error: { kind: "resolution", exitCode: 1 } });
	});

	it("reports the client's failure class at the provider error boundary", async () => {
		const outcome = await resolveSecrets([keepassSource("TOKEN", "keepassxc://absent-entry/password")], async () => {
			throw new KeePassXcError("keepassxc socket unavailable at test");
		});

		expect(outcome).toMatchObject({
			kind: "failure",
			secrets: [],
			error: { kind: "resolution", exitCode: 1 },
		});

		if (outcome.kind === "failure") {
			expect(outcome.error.message).toContain("keepassxc socket unavailable at test");
		}
	});

	it("reports a generic lookup failure for any other throw", async () => {
		const outcome = await resolveSecrets([keepassSource("TOKEN", "keepassxc://absent-entry/password")], async () => {
			throw new Error("raw-lookup-output synthetic-hidden-value");
		});

		expect(outcome).toMatchObject({ kind: "failure", secrets: [], error: { kind: "resolution", exitCode: 1 } });

		if (outcome.kind === "failure") {
			expect(outcome.error.message).toContain("keepassxc lookup failed");
			expect(outcome.error.message).not.toContain("synthetic-hidden-value");
		}
	});
});
