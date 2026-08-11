let initialized = false;

export async function ensureAsnInit(): Promise<void> {
	initialized = true;
}

export function wasInitialized(): boolean {
	return initialized;
}

export function resetInit(): void {
	initialized = false;
}
