import { createSecretRepresentations } from "./createSecretRepresentations";

const createPatterns = (values: Array<string>): Array<Buffer> => {
	const patterns = new Map<string, Buffer>();

	for (const value of values) {
		for (const representation of createSecretRepresentations(value)) {
			const pattern = Buffer.from(representation, "utf8");

			patterns.set(pattern.toString("hex"), pattern);
		}
	}

	return [...patterns.values()].sort((left, right) => right.length - left.length || Buffer.compare(left, right));
};

const peekByte = (input: Buffer, inputIndex: number, replay: Array<number>, offset: number): number | undefined => {
	if (offset < replay.length) {
		return replay[replay.length - 1 - offset];
	}

	return input[inputIndex + offset - replay.length];
};

const findPattern = (
	input: Buffer,
	inputIndex: number,
	replay: Array<number>,
	patterns: Array<Buffer>,
): Buffer | undefined => {
	const remainingBytes = replay.length + input.length - inputIndex;

	for (const pattern of patterns) {
		if (pattern.length > remainingBytes) {
			continue;
		}

		let matches = true;

		for (let offset = 0; offset < pattern.length; offset += 1) {
			if (peekByte(input, inputIndex, replay, offset) !== pattern[offset]) {
				matches = false;

				break;
			}
		}

		if (matches) {
			return pattern;
		}
	}

	return undefined;
};

const consumeBytes = (replay: Array<number>, inputIndex: number, count: number): number => {
	let remaining = count;

	while (remaining > 0 && replay.length > 0) {
		replay.pop();
		remaining -= 1;
	}

	return inputIndex + remaining;
};

export const redactBuffer = (input: Buffer, values: Array<string>): Buffer => {
	const patterns = createPatterns(values);

	if (patterns.length === 0 || input.length === 0) {
		return input;
	}

	const maximumPatternLength = patterns[0]?.length ?? 0;
	const output = Buffer.allocUnsafe(input.length);
	const replay: Array<number> = [];
	let inputIndex = 0;
	let outputLength = 0;
	let removed = false;

	while (replay.length > 0 || inputIndex < input.length) {
		const pattern = findPattern(input, inputIndex, replay, patterns);

		if (pattern === undefined) {
			const byte = replay.length > 0 ? replay.pop() : input[inputIndex++];

			if (byte !== undefined) {
				output[outputLength++] = byte;
			}

			continue;
		}

		inputIndex = consumeBytes(replay, inputIndex, pattern.length);
		removed = true;

		const replayCount = Math.min(maximumPatternLength - 1, outputLength);
		const replayStart = outputLength - replayCount;

		for (let index = outputLength - 1; index >= replayStart; index -= 1) {
			const byte = output[index];

			if (byte !== undefined) {
				replay.push(byte);
			}
		}

		outputLength = replayStart;
	}

	return removed ? Buffer.from(output.subarray(0, outputLength)) : input;
};
