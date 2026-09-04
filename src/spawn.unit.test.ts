import { mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { escapeArgument, escapeCommand, parseSpawn, readShebangCommand, resolveCommandPath } from "./spawn";

const fixtures: Array<string> = [];

afterEach(() => {
	for (const fixture of fixtures.splice(0)) {
		rmSync(fixture, { recursive: true, force: true });
	}
});

const createFixtureDirectory = (): string => {
	const directory = join(
		tmpdir(),
		`credact-spawn-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
	);

	mkdirSync(directory, { recursive: true });
	fixtures.push(directory);

	return directory;
};

describe("spawn resolution", () => {
	it("escapes cmd meta characters in commands and arguments", () => {
		expect(escapeCommand("a&b")).toBe("a^&b");
		expect(escapeArgument("hello world", false)).toBe('^"hello^ world^"');
		expect(escapeArgument('quote"here', false)).toBe('^"quote\\^"here^"');
		expect(escapeArgument("a&b", true)).toBe('^^^"a^^^&b^^^"');
	});

	it("reads a shebang binary name from a script file", () => {
		const directory = createFixtureDirectory();
		const scriptPath = join(directory, "tool");

		writeFileSync(scriptPath, "#!/usr/bin/env node\nconsole.log(1)\n");

		expect(readShebangCommand(scriptPath)).toBe("node");
	});

	it("reads a direct shebang path without env", () => {
		const directory = createFixtureDirectory();
		const scriptPath = join(directory, "tool");

		writeFileSync(scriptPath, "#!/usr/bin/node --experimental\n");

		expect(readShebangCommand(scriptPath)).toBe("node --experimental");
	});

	it("returns null when the file has no shebang", () => {
		const directory = createFixtureDirectory();
		const scriptPath = join(directory, "plain.txt");

		writeFileSync(scriptPath, "not a shebang\n");

		expect(readShebangCommand(scriptPath)).toBeNull();
	});

	it("resolves npm.cmd on Windows via PATHEXT", () => {
		if (process.platform !== "win32") {
			return;
		}

		const resolved = resolveCommandPath("npm.cmd");

		expect(resolved).toBeDefined();
		expect(resolved?.toLowerCase()).toMatch(/npm\.cmd$/u);
	});

	it("wraps non-exe Windows commands through cmd.exe", () => {
		if (process.platform !== "win32") {
			return;
		}

		const directory = createFixtureDirectory();
		const scriptPath = join(directory, "helper.cmd");

		writeFileSync(scriptPath, "@echo off\r\necho ok\r\n");

		const parsed = parseSpawn(scriptPath, ["arg with spaces"], { shell: false, env: process.env });

		expect(parsed.command.toLowerCase()).toMatch(/cmd\.exe$/u);
		expect(parsed.args.slice(0, 3)).toEqual(["/d", "/s", "/c"]);
		expect(parsed.options.windowsVerbatimArguments).toBe(true);
	});

	it("leaves native executables unwrapped on Windows", () => {
		if (process.platform !== "win32") {
			return;
		}

		const resolved = resolveCommandPath("node.exe") ?? resolveCommandPath("node");

		expect(resolved).toBeDefined();

		const parsed = parseSpawn(resolved as string, ["-e", "0"], { shell: false, env: process.env });

		expect(parsed.command.toLowerCase()).not.toMatch(/cmd\.exe$/u);
		expect(parsed.args).toEqual(["-e", "0"]);
	});

	it("resolves a shebang script and rewrites the command on Windows", () => {
		if (process.platform !== "win32") {
			return;
		}

		const directory = createFixtureDirectory();
		const scriptPath = join(directory, "with-shebang");

		writeFileSync(scriptPath, "#!/usr/bin/env node\nprocess.exit(0)\n");
		chmodSync(scriptPath, 0o755);

		const parsed = parseSpawn(scriptPath, [], {
			shell: false,
			env: { ...process.env, PATH: process.env.PATH },
		});

		expect(parsed.file).toBeDefined();
		expect(parsed.original.command).toBe(scriptPath);
	});
});
