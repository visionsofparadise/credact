#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL(".", import.meta.url));
const platformNames = { win32: "windows", linux: "linux", darwin: "darwin" };
const platformName = platformNames[process.platform];

if (platformName === undefined) {
	console.error(`no credact binary is built for ${process.platform}`);
	process.exit(1);
}

const bundlePath = join(repositoryRoot, "dist", "credact.js");
const binaryPath = join(
	repositoryRoot,
	"release",
	`credact-${platformName}-${process.arch}${process.platform === "win32" ? ".exe" : ""}`,
);

for (const artifact of [bundlePath, binaryPath]) {
	if (!existsSync(artifact)) {
		console.error(`missing artifact at ${artifact}`);
		process.exit(1);
	}
}

const launchers = [
	{ name: "npm bundle", command: process.execPath, prefix: [bundlePath] },
	{ name: "compiled executable", command: binaryPath, prefix: [] },
];

const usage = "Usage: credact [--no-output-scan] SOURCE [...] -- COMMAND [ARG ...]";
const absentSocket =
	process.platform === "win32"
		? `\\\\.\\pipe\\credact-smoke-absent-${randomUUID()}`
		: join(tmpdir(), `credact-smoke-absent-${randomUUID()}.sock`);

const is = (expected) => ({ description: `is ${JSON.stringify(expected)}`, matches: (actual) => actual === expected });
const startsWith = (expected) => ({
	description: `starts with ${JSON.stringify(expected)}`,
	matches: (actual) => actual.startsWith(expected),
});
const contains = (expected) => ({
	description: `contains ${JSON.stringify(expected)}`,
	matches: (actual) => actual.includes(expected),
});

const checks = [
	{
		name: "help",
		environment: {},
		args: ["--help"],
		exitCode: is(0),
		stdout: startsWith(usage),
		stderr: is(""),
	},
	{
		name: "environment source scrubbed",
		environment: { SMOKE_SECRET: "hunter2-smoke-value" },
		args: [
			"SMOKE_SECRET",
			"--",
			process.execPath,
			"-e",
			"process.stdout.write(process.env.SMOKE_SECRET + '|'); process.stderr.write(Buffer.from(process.env.SMOKE_SECRET).toString('base64') + '|')",
		],
		exitCode: is(0),
		stdout: is("|"),
		stderr: is("|"),
	},
	{
		name: "missing source fails closed",
		environment: { ABSENT_SMOKE: undefined },
		args: ["ABSENT_SMOKE", "--", process.execPath, "-e", "process.stdout.write('ran')"],
		exitCode: is(1),
		stdout: is(""),
		stderr: contains("credact: ABSENT_SMOKE: environment value was absent"),
	},
	{
		name: "unreachable KeePassXC fails closed",
		environment: { KEEPASSXC_BROWSER_SOCKET_PATH: absentSocket },
		args: ["SMOKE_REFERENCE=keepassxc://smoke/password", "--", process.execPath, "-e", "process.stdout.write('ran')"],
		exitCode: is(1),
		stdout: is(""),
		stderr: startsWith("credact: SMOKE_REFERENCE: "),
	},
];

const environmentOf = (overrides) => {
	const environment = {};

	for (const [name, value] of Object.entries(process.env)) {
		if (Object.hasOwn(overrides, name)) {
			continue;
		}

		environment[name] = value;
	}

	for (const [name, value] of Object.entries(overrides)) {
		if (value === undefined) {
			continue;
		}

		environment[name] = value;
	}

	return environment;
};

const fail = (check, launcher, comparison, expectation, actual) => {
	console.error(`${check.name} [${launcher.name}]: ${comparison} ${expectation.description}`);
	console.error(`  actual ${JSON.stringify(actual)}`);
	process.exit(1);
};

for (const launcher of launchers) {
	for (const check of checks) {
		const result = spawnSync(launcher.command, [...launcher.prefix, ...check.args], {
			cwd: repositoryRoot,
			env: environmentOf(check.environment),
			encoding: "utf8",
			timeout: 60_000,
		});

		if (result.error !== undefined) {
			console.error(`${check.name} [${launcher.name}]: ${result.error.message}`);
			process.exit(1);
		}

		for (const [comparison, expectation, actual] of [
			["exit code", check.exitCode, result.status],
			["stdout", check.stdout, result.stdout],
			["stderr", check.stderr, result.stderr],
		]) {
			if (!expectation.matches(actual)) {
				fail(check, launcher, comparison, expectation, actual);
			}
		}

		console.log(`ok ${check.name} [${launcher.name}]`);
	}
}
