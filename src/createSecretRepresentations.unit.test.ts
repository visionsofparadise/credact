import { describe, expect, it } from "vitest";
import { createSecretRepresentations } from "./createSecretRepresentations";

describe("createSecretRepresentations", () => {
	it("creates the bounded common representation set", () => {
		expect(createSecretRepresentations('z "b')).toEqual([
			'z "b',
			'z \\"b',
			"z%20%22b",
			"z+%22b",
			"eiAiYg==",
			"eiAiYg",
			"7a202262",
			"7A202262",
		]);
	});

	it("creates distinct standard and URL-safe Base64 forms", () => {
		const representations = createSecretRepresentations("🔐");

		expect(representations).toContain("8J+UkA==");
		expect(representations).toContain("8J-UkA==");
		expect(representations).toContain("8J-UkA");
	});

	it("ignores an empty value", () => {
		expect(createSecretRepresentations("")).toEqual([]);
	});
});
