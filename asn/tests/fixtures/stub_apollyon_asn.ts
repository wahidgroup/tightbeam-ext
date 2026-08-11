function jsonCodec() {
	const encode = (value: unknown) =>
		new TextEncoder().encode(JSON.stringify(value));
	const decode = (bytes: Uint8Array) =>
		JSON.parse(new TextDecoder().decode(bytes));
	return { encode, decode };
}

const doc = jsonCodec();
const status = jsonCodec();

export function encodeDoc(value: unknown): Uint8Array {
	return doc.encode(value);
}

export function decodeDoc(bytes: Uint8Array): unknown {
	return doc.decode(bytes);
}

export function encodeStatusReport(value: unknown): Uint8Array {
	return status.encode(value);
}

export function decodeStatusReport(bytes: Uint8Array): unknown {
	return status.decode(bytes);
}
