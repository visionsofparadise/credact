#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const require = createRequire(import.meta.url);
const repositoryRoot = fileURLToPath(new URL(".", import.meta.url));
const bunBinary = join(dirname(require.resolve("bun/package.json")), "bin", "bun.exe");

const targets = {
	"windows-x64": { bunTarget: "bun-windows-x64", extension: ".exe" },
	"windows-arm64": { bunTarget: "bun-windows-arm64", extension: ".exe" },
	"linux-x64": { bunTarget: "bun-linux-x64", extension: "" },
	"linux-arm64": { bunTarget: "bun-linux-arm64", extension: "" },
	"darwin-arm64": { bunTarget: "bun-darwin-arm64", extension: "" },
	"darwin-x64": { bunTarget: "bun-darwin-x64", extension: "" },
};

const binaries = [{ name: "credact", entry: "src/credact.ts" }];

const { values } = parseArgs({ options: { target: { type: "string", multiple: true } } });
const selectedTargets = values.target ?? Object.keys(targets);

for (const targetName of selectedTargets) {
	if (!Object.hasOwn(targets, targetName)) {
		console.error(`unknown target ${targetName}; build.mjs builds ${Object.keys(targets).join(", ")}`);
		process.exit(1);
	}
}

for (const targetName of selectedTargets) {
	const { bunTarget, extension } = targets[targetName];

	for (const binary of binaries) {
		const outputFile = join("release", `${binary.name}-${targetName}${extension}`);
		const result = spawnSync(
			bunBinary,
			["build", "--compile", "--minify", `--target=${bunTarget}`, "--outfile", outputFile, binary.entry],
			{ cwd: repositoryRoot, stdio: "inherit" },
		);

		if (result.error !== undefined) {
			console.error(result.error.message);
			process.exit(1);
		}

		if (result.status !== 0) {
			console.error(`bun build ${outputFile} exited ${String(result.status)}`);
			process.exit(result.status ?? 1);
		}
	}
}
