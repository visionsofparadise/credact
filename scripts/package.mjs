import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { versionOf } from "./release.mjs";

export const targets = {
	"x86_64-pc-windows-msvc": {
		binarySuffix: ".exe",
		formats: [{ format: "nsis", sourceSuffix: "_x64-setup.exe", destinationSuffix: "-windows-x64.exe" }],
	},
	"aarch64-pc-windows-msvc": {
		binarySuffix: ".exe",
		formats: [{ format: "nsis", sourceSuffix: "_arm64-setup.exe", destinationSuffix: "-windows-arm64.exe" }],
	},
	"x86_64-unknown-linux-musl": {
		binarySuffix: "",
		formats: [
			{ format: "appimage", sourceSuffix: "_x86_64.AppImage", destinationSuffix: "-linux-x86_64.AppImage" },
			{ format: "deb", sourceSuffix: "_amd64.deb", destinationSuffix: "-linux-amd64.deb" },
		],
	},
	"aarch64-unknown-linux-musl": { binarySuffix: "", formats: [] },
	"aarch64-apple-darwin": {
		binarySuffix: "",
		formats: [{ format: "dmg", sourceSuffix: "_aarch64.dmg", destinationSuffix: "-mac-arm64.dmg" }],
	},
	"x86_64-apple-darwin": {
		binarySuffix: "",
		formats: [{ format: "dmg", sourceSuffix: "_x64.dmg", destinationSuffix: "-mac-x64.dmg" }],
	},
};

function targetOf(triple) {
	if (!Object.hasOwn(targets, triple)) throw new Error(`Unknown target triple: ${triple}`);

	return targets[triple];
}

export function packageNamesOf(version, triple) {
	return targetOf(triple).formats.map(({ format, sourceSuffix, destinationSuffix }) => ({
		format,
		source: `credact_${version}${sourceSuffix}`,
		destination: `credact-${version}${destinationSuffix}`,
	}));
}

export function normalizePackages(root, version, triple) {
	const output = join(root, "out", "make");

	mkdirSync(output, { recursive: true });

	const directory = join(root, "target", triple, "release");

	return packageNamesOf(version, triple).map(({ format, source, destination }) => {
		const extension = source.slice(source.lastIndexOf("."));
		const candidates = readdirSync(directory).filter(
			(file) => file.includes(`_${version}_`) && file.endsWith(extension),
		);

		if (candidates.length !== 1)
			throw new Error(`Expected exactly one ${format} package for ${version}; found ${candidates.length}`);

		const packaged = join(output, destination);

		copyFileSync(join(directory, candidates[0]), packaged);

		return packaged;
	});
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const triple = process.argv[2];
	const { binarySuffix, formats } = targetOf(triple);
	const version = versionOf();
	const root = fileURLToPath(new URL("..", import.meta.url));
	const output = join(root, "out", "make");

	execFileSync("cargo", ["build", "--locked", "--release", "--target", triple], { stdio: "inherit" });
	mkdirSync(output, { recursive: true });
	copyFileSync(
		join(root, "target", triple, "release", `credact${binarySuffix}`),
		join(output, `credact-${version}-${triple}${binarySuffix}`),
	);

	for (const { format } of formats)
		execFileSync("cargo", ["packager", "--release", "--target", triple, "-f", format], { stdio: "inherit" });

	for (const packaged of normalizePackages(root, version, triple)) console.log(packaged);
}
