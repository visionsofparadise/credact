const encodeUrl = (value: string): string | undefined => {
	try {
		return encodeURIComponent(value);
	} catch {
		return undefined;
	}
};

export const createSecretRepresentations = (value: string): Array<string> => {
	const bytes = Buffer.from(value, "utf8");
	const base64 = bytes.toString("base64");
	const base64UrlPadded = base64.replaceAll("+", "-").replaceAll("/", "_");
	const hex = bytes.toString("hex");
	const representations = [
		value,
		JSON.stringify(value).slice(1, -1),
		encodeUrl(value),
		new URLSearchParams([["value", value]]).toString().slice("value=".length),
		base64,
		base64UrlPadded,
		base64UrlPadded.replace(/=+$/u, ""),
		hex,
		hex.toUpperCase(),
	];

	return [
		...new Set(
			representations.filter(
				(representation): representation is string => representation !== undefined && representation.length > 0,
			),
		),
	];
};
