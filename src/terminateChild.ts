import type { ChildProcess } from "node:child_process";
import type { Readable, Writable } from "node:stream";

const gracefulTerminationMilliseconds = 250;
const forcedTerminationMilliseconds = 5_000;

const destroyStreams = (streams: Array<Readable | Writable | null>): void => {
	for (const stream of streams) {
		stream?.destroy();
	}
};

export const terminateChild = async (
	child: ChildProcess,
	streams: Array<Readable | Writable | null> = [],
): Promise<void> => {
	if (child.exitCode !== null || child.signalCode !== null) {
		destroyStreams(streams);

		return;
	}

	try {
		await new Promise<void>((resolve, reject) => {
			let settled = false;
			const timers = new Set<NodeJS.Timeout>();

			const finish = (action: () => void): void => {
				if (settled) {
					return;
				}

				settled = true;

				for (const timer of timers) {
					clearTimeout(timer);
				}

				child.removeListener("exit", handleExit);
				child.removeListener("error", handleError);
				action();
			};
			const handleExit = (): void => finish(resolve);
			const handleError = (): void => finish(() => reject(new Error("child termination failed")));

			child.once("exit", handleExit);
			child.once("error", handleError);

			try {
				child.kill("SIGTERM");
			} catch {
				finish(() => reject(new Error("child termination failed")));

				return;
			}

			timers.add(
				setTimeout(() => {
					try {
						child.kill("SIGKILL");
					} catch {
						finish(() => reject(new Error("child forced termination failed")));
					}
				}, gracefulTerminationMilliseconds),
			);
			timers.add(
				setTimeout(() => finish(() => reject(new Error("child did not terminate"))), forcedTerminationMilliseconds),
			);
		});
	} finally {
		destroyStreams(streams);
	}
};
