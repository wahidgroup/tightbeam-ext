/**
 * The base64 decode that the ws pages and the pubsub fixtures share, as `docs/ws.md` (Test support) states it.
 */

/**
 * Decode a base64 string, such as a DER or key that crossed the
 * `page.evaluate` boundary or a query parameter, into bytes.
 */
export function base64ToBytes(base64: string): Uint8Array {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i);
	}

	return bytes;
}
