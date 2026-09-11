import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function runGh(arguments_) {
	return execFileSync("gh", arguments_, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function api(endpoint, run) {
	try {
		return JSON.parse(run(["api", endpoint]));
	} catch (error) {
		if (error && typeof error === "object" && "stdout" in error) {
			let response;

			try {
				response = JSON.parse(String(error.stdout));
			} catch {
				throw error;
			}

			if (response.status === "404" && response.message === "Not Found") return null;
		}

		throw error;
	}
}

export function versionOf() {
	return JSON.parse(
		execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "inherit"],
		}),
	).packages[0].version;
}

export function artifactNamesOf(version) {
	if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.test(version))
		throw new Error("Release version must be a stable major.minor.patch version");

	return [
		`credact-${version}-windows-x64.exe`,
		`credact-${version}-windows-arm64.exe`,
		`credact-${version}-mac-arm64.dmg`,
		`credact-${version}-mac-x64.dmg`,
		`credact-${version}-linux-x86_64.AppImage`,
		`credact-${version}-linux-amd64.deb`,
		`credact-${version}-x86_64-pc-windows-msvc.exe`,
		`credact-${version}-aarch64-pc-windows-msvc.exe`,
		`credact-${version}-x86_64-unknown-linux-musl`,
		`credact-${version}-aarch64-unknown-linux-musl`,
		`credact-${version}-aarch64-apple-darwin`,
		`credact-${version}-x86_64-apple-darwin`,
	].sort();
}

export function releaseAssetNamesOf(version) {
	return [...artifactNamesOf(version), "THIRD-PARTY-NOTICES.txt"].sort();
}

function checksumOf(directory, version) {
	return releaseAssetNamesOf(version)
		.map((asset) => {
			const digest = createHash("sha256")
				.update(readFileSync(join(directory, asset)))
				.digest("hex");

			return `${digest}  ${asset}\n`;
		})
		.join("");
}

export function writeChecksums(directory, version) {
	writeFileSync(join(directory, "SHA256SUMS"), checksumOf(directory, version));
}

function tagTargetOf(repository, tag, run) {
	const reference = api(`repos/${repository}/git/ref/tags/${tag}`, run);

	if (!reference) return null;

	let object = reference.object;

	for (let depth = 0; object?.type === "tag" && depth < 10; depth++)
		object = api(`repos/${repository}/git/tags/${object.sha}`, run)?.object;

	if (object?.type !== "commit" || !/^[a-f0-9]{40}$/u.test(object.sha))
		throw new Error("Release tag does not resolve to a commit");

	return object.sha;
}

export function publishRelease({ repository, sha, version, directory, draftOnly = false, run = runGh }) {
	const assets = releaseAssetNamesOf(version);

	if (!/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/u.test(repository) || !/^[a-f0-9]{40}$/u.test(sha))
		throw new Error("A repository and exact triggering commit are required");

	const expected = checksumOf(directory, version);

	if (readFileSync(join(directory, "SHA256SUMS"), "utf8") !== expected)
		throw new Error("Release asset checksum does not match SHA256SUMS");

	const tag = `v${version}`;
	const release = api(`repos/${repository}/releases/tags/${tag}`, run);

	if (release && !release.draft) return "already published";

	const target = tagTargetOf(repository, tag, run);

	if (target && target !== sha) throw new Error("Release tag targets another commit");

	if (release && !target && release.target_commitish !== sha) throw new Error("Draft release targets another commit");

	if (!release)
		run([
			"release",
			"create",
			tag,
			"--repo",
			repository,
			"--target",
			sha,
			"--draft",
			"--title",
			`credact ${version}`,
			"--notes",
			"Windows x64 and arm64 installers, macOS Apple Silicon and Intel DMGs, a Linux x64 AppImage and Debian package, and a raw binary for every target named by Rust target triple. SHA256SUMS covers every download. Builds are not code signed or notarized.",
		]);

	run([
		"release",
		"upload",
		tag,
		...assets.map((asset) => join(directory, asset)),
		join(directory, "SHA256SUMS"),
		"--repo",
		repository,
		"--clobber",
	]);
	const scratch = resolve(".scratch");

	mkdirSync(scratch, { recursive: true });

	const verification = mkdtempSync(join(scratch, "release-verify-"));

	try {
		run([
			"release",
			"download",
			tag,
			"--repo",
			repository,
			"--dir",
			verification,
			...assets.flatMap((asset) => ["--pattern", asset]),
			"--pattern",
			"SHA256SUMS",
		]);

		if (
			checksumOf(verification, version) !== expected ||
			readFileSync(join(verification, "SHA256SUMS"), "utf8") !== expected
		)
			throw new Error("Uploaded release assets failed checksum verification");
	} finally {
		rmSync(verification, { recursive: true });
	}

	const currentTarget = tagTargetOf(repository, tag, run);

	if (currentTarget && currentTarget !== sha) throw new Error("Release tag changed during upload");

	if (draftOnly) return "draft ready for review";

	run(["release", "edit", tag, "--repo", repository, "--draft=false", "--latest"]);

	if (tagTargetOf(repository, tag, run) !== sha) throw new Error("Published release tag has an unexpected target");

	return "published";
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const [command, directory = fileURLToPath(new URL("../out/make", import.meta.url))] = process.argv.slice(2);
	const version = versionOf();

	if (command === "checksums") writeChecksums(directory, version);
	else if (command === "publish")
		console.log(
			publishRelease({
				repository: process.env.GITHUB_REPOSITORY,
				sha: process.env.GITHUB_SHA,
				version,
				directory,
				draftOnly: process.env.RELEASE_DRAFT_ONLY === "true",
			}),
		);
	else throw new Error("Usage: node scripts/release.mjs checksums|publish [asset-directory]");
}
