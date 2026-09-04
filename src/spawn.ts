import { spawn as nodeSpawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { openSync, readSync, closeSync, statSync } from "node:fs";
import { join, normalize, resolve } from "node:path";

export interface SpawnInvocation {
	readonly command: string;
	readonly args: Array<string>;
	readonly options: SpawnOptions;
	readonly file: string | undefined;
	readonly original: {
		readonly command: string;
		readonly args: Array<string>;
	};
}

const isWindows = process.platform === "win32";
const executablePattern = /\.(?:com|exe)$/iu;
const cmdShimPattern = /node_modules[\\/].bin[\\/][^\\/]+\.cmd$/iu;
const metaCharsPattern = /([()\][%!^"`<>&|;, *?])/gu;
const shebangPattern = /^#! ?(.*)/u;

const pathEnvironmentKey = (environment: NodeJS.ProcessEnv): string => {
	if (!isWindows) {
		return "PATH";
	}

	return (
		Object.keys(environment)
			.reverse()
			.find((key) => key.toUpperCase() === "PATH") ?? "Path"
	);
};

const isExecutableFile = (filePath: string, pathExtValue: string): boolean => {
	try {
		const stats = statSync(filePath);

		if (!stats.isFile() && !stats.isSymbolicLink()) {
			return false;
		}
	} catch {
		return false;
	}

	if (!isWindows || pathExtValue.length === 0) {
		return true;
	}

	const extensions = pathExtValue.split(";");

	if (extensions.includes("")) {
		return true;
	}

	const lowerPath = filePath.toLowerCase();

	return extensions.some((extension) => extension.length > 0 && lowerPath.endsWith(extension.toLowerCase()));
};

const whichSync = (
	commandName: string,
	searchPath: string | undefined,
	withoutPathExt: boolean,
): string | undefined => {
	const colon = isWindows ? ";" : ":";
	const hasDirectory = commandName.includes("/") || (isWindows && commandName.includes("\\"));
	const pathEnv = hasDirectory
		? [""]
		: [...(isWindows ? [process.cwd()] : []), ...(searchPath ?? process.env.PATH ?? "").split(colon)];
	const pathExtExe = isWindows ? (withoutPathExt ? "" : (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM")) : "";
	const pathExt = isWindows ? (pathExtExe.length === 0 ? [""] : pathExtExe.split(colon)) : [""];

	if (isWindows && commandName.includes(".") && pathExt[0] !== "") {
		pathExt.unshift("");
	}

	for (const pathPartRaw of pathEnv) {
		const pathPart = /^".*"$/u.test(pathPartRaw) ? pathPartRaw.slice(1, -1) : pathPartRaw;
		const joined = join(pathPart, commandName);
		const candidateBase = !pathPart && /^\.[\\/]/u.test(commandName) ? commandName.slice(0, 2) + joined : joined;

		for (const extension of pathExt) {
			const candidate = candidateBase + extension;

			if (isExecutableFile(candidate, pathExtExe)) {
				return candidate;
			}
		}
	}

	return undefined;
};

const resolveCommand = (parsed: SpawnInvocation, withoutPathExt = false): string | undefined => {
	const environment = parsed.options.env ?? process.env;
	const workingDirectory = process.cwd();
	const hasCustomCwd = parsed.options.cwd !== undefined;
	const shouldSwitchCwd =
		hasCustomCwd && typeof process.chdir === "function" && !(process.chdir as { disabled?: boolean }).disabled;
	let resolved: string | undefined;

	if (shouldSwitchCwd) {
		try {
			process.chdir(parsed.options.cwd as string);
		} catch {
			void 0;
		}
	}

	try {
		resolved = whichSync(parsed.command, environment[pathEnvironmentKey(environment)], withoutPathExt);
	} finally {
		if (shouldSwitchCwd) {
			process.chdir(workingDirectory);
		}
	}

	if (resolved !== undefined) {
		const base = hasCustomCwd ? String(parsed.options.cwd ?? "") : "";

		return resolve(base, resolved);
	}

	return undefined;
};

const resolveCommandWithFallback = (parsed: SpawnInvocation): string | undefined =>
	resolveCommand(parsed) ?? resolveCommand(parsed, true);

const readShebang = (commandPath: string): string | null => {
	const size = 150;
	const buffer = Buffer.alloc(size);
	let fileDescriptor: number | undefined;

	try {
		fileDescriptor = openSync(commandPath, "r");
		readSync(fileDescriptor, buffer, 0, size, 0);
	} catch {
		return null;
	} finally {
		if (fileDescriptor !== undefined) {
			closeSync(fileDescriptor);
		}
	}

	const match = shebangPattern.exec(buffer.toString());

	if (match?.[1] === undefined) {
		return null;
	}

	const [pathPart, argument] = match[1].trim().split(" ");
	const binary = (pathPart ?? "").split("/").pop() ?? "";

	if (binary === "env") {
		return argument ?? null;
	}

	return argument !== undefined && argument.length > 0 ? `${binary} ${argument}` : binary || null;
};

export const escapeCommand = (argument: string): string => argument.replace(metaCharsPattern, "^$1");

export const escapeArgument = (argument: string, doubleEscapeMetaChars: boolean): string => {
	let escaped = argument;

	escaped = escaped.replace(/(?=(\\+?)?)\1"/gu, '$1$1\\"');
	escaped = escaped.replace(/(?=(\\+?)?)\1$/gu, "$1$1");
	escaped = `"${escaped}"`;
	escaped = escaped.replace(metaCharsPattern, "^$1");

	if (doubleEscapeMetaChars) {
		escaped = escaped.replace(metaCharsPattern, "^$1");
	}

	return escaped;
};

const detectShebang = (parsed: SpawnInvocation): string | undefined => {
	const mutable = parsed as SpawnInvocation & { file: string | undefined; command: string; args: Array<string> };

	mutable.file = resolveCommandWithFallback(parsed);

	const resolvedFile = mutable.file;
	const shebang = resolvedFile === undefined ? null : readShebang(resolvedFile);

	if (shebang !== null && resolvedFile !== undefined) {
		mutable.args.unshift(resolvedFile);
		mutable.command = shebang;

		return resolveCommandWithFallback(mutable);
	}

	return mutable.file;
};

const parseNonShell = (parsed: SpawnInvocation): SpawnInvocation => {
	if (!isWindows) {
		return parsed;
	}

	const mutable = parsed as SpawnInvocation & {
		command: string;
		args: Array<string>;
		options: SpawnOptions;
		file: string | undefined;
	};
	const commandFile = detectShebang(mutable) ?? "";
	const needsShell = !executablePattern.test(commandFile);
	const forceShell = Boolean((mutable.options as { forceShell?: boolean }).forceShell);

	if (forceShell || needsShell) {
		const needsDoubleEscapeMetaChars = cmdShimPattern.test(commandFile);

		mutable.command = normalize(mutable.command);
		mutable.command = escapeCommand(mutable.command);
		mutable.args = mutable.args.map((argument) => escapeArgument(argument, needsDoubleEscapeMetaChars));

		const shellCommand = [mutable.command, ...mutable.args].join(" ");

		mutable.args = ["/d", "/s", "/c", `"${shellCommand}"`];
		mutable.command = process.env.comspec ?? "cmd.exe";
		mutable.options.windowsVerbatimArguments = true;
	}

	return mutable;
};

export const parseSpawn = (
	command: string,
	args: Array<string> | SpawnOptions | undefined,
	options?: SpawnOptions,
): SpawnInvocation => {
	let commandArgs: Array<string>;
	let spawnOptions: SpawnOptions;

	if (args !== undefined && !Array.isArray(args)) {
		spawnOptions = { ...args };
		commandArgs = [];
	} else {
		commandArgs = args === undefined ? [] : [...args];
		spawnOptions = options === undefined ? {} : { ...options };
	}

	const parsed: SpawnInvocation = {
		command,
		args: commandArgs,
		options: spawnOptions,
		file: undefined,
		original: {
			command,
			args: commandArgs,
		},
	};

	return spawnOptions.shell === true ? parsed : parseNonShell(parsed);
};

const notFoundError = (original: SpawnInvocation["original"], syscall: string): Error =>
	Object.assign(new Error(`${syscall} ${original.command} ENOENT`), {
		code: "ENOENT",
		errno: "ENOENT",
		syscall: `${syscall} ${original.command}`,
		path: original.command,
		spawnargs: original.args,
	});

const verifyEnoent = (status: number | null, parsed: SpawnInvocation): Error | null => {
	if (isWindows && status === 1 && parsed.file === undefined) {
		return notFoundError(parsed.original, "spawn");
	}

	return null;
};

const hookChildProcess = (child: ChildProcess, parsed: SpawnInvocation): void => {
	if (!isWindows) {
		return;
	}

	const originalEmit = child.emit.bind(child);

	child.emit = ((event: string | symbol, ...eventArgs: Array<unknown>): boolean => {
		if (event === "exit") {
			const status = typeof eventArgs[0] === "number" || eventArgs[0] === null ? eventArgs[0] : null;
			const enoent = verifyEnoent(status, parsed);

			if (enoent !== null) {
				return originalEmit("error", enoent);
			}
		}

		return originalEmit(event, ...eventArgs);
	}) as ChildProcess["emit"];
};

export const spawn = (command: string, args?: Array<string> | SpawnOptions, options?: SpawnOptions): ChildProcess => {
	const parsed = parseSpawn(command, args, options);
	const child = nodeSpawn(parsed.command, parsed.args, parsed.options);

	hookChildProcess(child, parsed);

	return child;
};

export const resolveCommandPath = (
	command: string,
	environment: NodeJS.ProcessEnv = process.env,
): string | undefined => {
	const parsed: SpawnInvocation = {
		command,
		args: [],
		options: { env: environment, shell: false },
		file: undefined,
		original: {
			command,
			args: [],
		},
	};

	return resolveCommandWithFallback(parsed);
};

export const readShebangCommand = (commandPath: string): string | null => readShebang(commandPath);
