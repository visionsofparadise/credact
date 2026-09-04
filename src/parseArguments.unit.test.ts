import { describe, expect, it } from "vitest";
import { parseArguments, CredactError } from "./parseArguments";

const expectUsageFailure = (arguments_: Array<string>): void => {
	expect(() => parseArguments(arguments_)).toThrow(CredactError);

	try {
		parseArguments(arguments_);
	} catch (failure) {
		expect(failure).toMatchObject({ kind: "usage", exitCode: 2 });
	}
};

describe("parseArguments", () => {
	it("returns help only for a sole help token", () => {
		expect(parseArguments(["--help"])).toEqual({ kind: "help" });
		expectUsageFailure(["--help", "--", "node"]);
	});

	it("parses environment, KeePassXC, and passthrough sources", () => {
		expect(parseArguments(["TOKEN=keepassxc://service/password", "--", "node"])).toEqual({
			kind: "run",
			invocation: {
				command: "node",
				commandArguments: [],
				scanOutput: true,
				sources: [{ kind: "keepassxc", name: "TOKEN", reference: "keepassxc://service/password" }],
			},
		});
		expect(parseArguments(["--no-output-scan", "TOKEN", "--", "node"])).toMatchObject({
			kind: "run",
			invocation: { scanOutput: false, sources: [{ kind: "environment", name: "TOKEN" }] },
		});
	});

	it("preserves mixed sources and command arguments", () => {
		const result = parseArguments([
			"FIRST",
			"SECOND=keepassxc://two/custom-field",
			"--",
			"program with spaces",
			"--option=value",
			"argument with spaces",
			"--",
		]);

		expect(result).toEqual({
			kind: "run",
			invocation: {
				command: "program with spaces",
				commandArguments: ["--option=value", "argument with spaces", "--"],
				scanOutput: true,
				sources: [
					{ kind: "environment", name: "FIRST" },
					{ kind: "keepassxc", name: "SECOND", reference: "keepassxc://two/custom-field" },
				],
			},
		});
	});

	it("rejects case-insensitive duplicate names", () => {
		expectUsageFailure(["Token", "TOKEN=keepassxc://two/password", "--", "node"]);
	});

	const invalidInvocations: Array<Array<string>> = [
		[],
		["TOKEN=keepassxc://service/password", "node"],
		["--", "node"],
		["TOKEN=keepassxc://service/password", "--"],
		["TOKEN=keepassxc://service/password", "--", ""],
		["1TOKEN", "--", "node"],
		["1TOKEN=keepassxc://service/password", "--", "node"],
		["TOKEN=", "--", "node"],
		["TOKEN=https://service/password", "--", "node"],
		["TOKEN=keepassxc://service", "--", "node"],
		["TOKEN=keepassxc://service/", "--", "node"],
		["TOKEN=keepassxc://service/password?mode=test", "--", "node"],
		["TOKEN=keepassxc://service/password?", "--", "node"],
		["TOKEN=keepassxc://service/password#fragment", "--", "node"],
		["TOKEN=keepassxc://service/password#", "--", "node"],
		["TOKEN=keepassxc:///password", "--", "node"],
		["TOKEN=keepassxc://service/password", "--no-output-scan", "--", "node"],
		["--no-output-scan", "--no-output-scan", "TOKEN=keepassxc://service/password", "--", "node"],
	];

	it.each(invalidInvocations.map((arguments_) => [arguments_] as const))(
		"rejects invalid invocation %#",
		(arguments_) => {
			expectUsageFailure(arguments_);
		},
	);
});
