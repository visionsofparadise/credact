import { describe, expect, it } from "vitest";
import { redactBuffer } from "./redactBuffer";

const expectRedaction = (input: Buffer, values: Array<string>, expected: Buffer): void => {
	const output = redactBuffer(input, values);

	expect(output).toEqual(expected);

	for (const value of values) {
		const pattern = Buffer.from(value, "utf8");

		if (pattern.length > 0) {
			expect(output.includes(pattern)).toBe(false);
		}
	}
};

const redactNaively = (input: Buffer, values: Array<string>): Buffer => {
	const patterns = [...new Map(values.map((value) => [value, Buffer.from(value)])).values()]
		.filter((pattern) => pattern.length > 0)
		.sort((left, right) => right.length - left.length || Buffer.compare(left, right));
	let output = input;

	while (true) {
		let removed = false;

		for (let index = 0; index < output.length; index += 1) {
			const pattern = patterns.find((candidate) =>
				output.subarray(index, index + candidate.length).equals(candidate),
			);

			if (pattern === undefined) {
				continue;
			}

			output = Buffer.concat([output.subarray(0, index), output.subarray(index + pattern.length)]);
			removed = true;
			break;
		}

		if (!removed) {
			return output;
		}
	}
};

describe("redactBuffer", () => {
	it.each([
		["secret-tail", "-tail"],
		["head-secret-tail", "head--tail"],
		["head-secret", "head-"],
		["secretsecret", ""],
		["secret-secret", "-"],
	])("removes literal matches from %s", (input, expected) => {
		expectRedaction(Buffer.from(input), ["secret"], Buffer.from(expected));
	});

	it("uses the longest pattern at a shared start", () => {
		expectRedaction(Buffer.from("abcab"), ["ab", "abc", "ab"], Buffer.alloc(0));
	});

	it("rescans after deletion synthesizes another active value", () => {
		expectRedaction(Buffer.from("abXc"), ["abc", "X"], Buffer.alloc(0));
	});

	it("matches UTF-8 byte sequences", () => {
		expectRedaction(Buffer.from("before-🔐秘密-after"), ["🔐秘密"], Buffer.from("before--after"));
	});

	it("removes common escaped and encoded representations", () => {
		const representations = ['z "b', 'z \\"b', "z%20%22b", "z+%22b", "eiAiYg==", "eiAiYg", "7a202262", "7A202262"];

		expectRedaction(
			Buffer.from(representations.join("|")),
			['z "b'],
			Buffer.from("|".repeat(representations.length - 1)),
		);
	});

	it("preserves binary and NUL surroundings", () => {
		expectRedaction(
			Buffer.concat([Buffer.from([0, 255, 1]), Buffer.from("secret"), Buffer.from([2, 0, 254])]),
			["secret"],
			Buffer.from([0, 255, 1, 2, 0, 254]),
		);
	});

	it("returns the original clean buffer", () => {
		const input = Buffer.from("clean output with secre prefix");

		expect(redactBuffer(input, ["secret"])).toBe(input);
	});

	it("leaves incomplete prefixes and an empty input unchanged", () => {
		expectRedaction(Buffer.from("secre"), ["secret"], Buffer.from("secre"));
		expect(redactBuffer(Buffer.alloc(0), ["secret"])).toEqual(Buffer.alloc(0));
	});

	it("ignores empty values defensively", () => {
		const input = Buffer.from("unchanged");

		expect(redactBuffer(input, ["", ""])).toBe(input);
	});

	it("handles many generations of synthesized boundary matches", () => {
		const pairs = 4_000;
		const input = Buffer.from(`${"a".repeat(pairs)}X${"b".repeat(pairs)}`);

		expect(redactBuffer(input, ["X", "ab"])).toEqual(Buffer.alloc(0));
	}, 2_000);

	it("matches the leftmost-longest fixed-point definition exhaustively on small inputs", () => {
		const alphabet = ["a", "b", "c"];
		const patternSets = [
			["a", "ab"],
			["ab", "abc", "bc"],
			["b", "ac", "abc"],
			["aa", "aab", "ba"],
		];
		let inputs = [""];

		for (let length = 1; length <= 7; length += 1) {
			inputs = [
				...inputs,
				...inputs
					.filter((input) => input.length === length - 1)
					.flatMap((input) => alphabet.map((byte) => input + byte)),
			];
		}

		for (const input of inputs) {
			for (const patterns of patternSets) {
				const bytes = Buffer.from(input);

				expect(redactBuffer(bytes, patterns), JSON.stringify({ input, patterns })).toEqual(
					redactNaively(bytes, patterns),
				);
			}
		}
	});
});
