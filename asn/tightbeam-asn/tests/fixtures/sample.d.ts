/* tslint:disable */
/* eslint-disable */
// The parser input of the refusal path: an encode without its decode, where a real wasm build declares both, a decode
// export that names no type, pairs whose signatures are not those of the derive, and a pair of a name that the emitted
// module uses.
export interface Doc {
	title: string;
}

export interface StatusReport {
	status: number;
}

export interface Pick {
	title: string;
}

export function decodeDoc(bytes: Uint8Array): Doc;
export function decodeStatusReport(bytes: Uint8Array): StatusReport;
export function encodeDoc(value: Doc): Uint8Array;
export function encodeStatusReport(value: StatusReport): Uint8Array;
export function encodeOrphan(value: Doc): Uint8Array;
export function decode64(bytes: Uint8Array): Uint8Array;
export function encode_frame(frame: Uint8Array): Uint8Array;
export function decode_frame(bytes: Uint8Array): Uint8Array;
export function encodeBase64(text: string): string;
export function decodeBase64(text: string): string;
export function encodePick(value: Pick): Uint8Array;
export function decodePick(bytes: Uint8Array): Pick;
