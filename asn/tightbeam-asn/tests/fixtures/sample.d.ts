/* tslint:disable */
/* eslint-disable */
// The parser input of the refusal path: an encode with no decode, which a
// real wasm build never declares.
export interface Doc {
	title: string;
}

export interface StatusReport {
	status: number;
}

export function decodeDoc(bytes: Uint8Array): Doc;
export function decodeStatusReport(bytes: Uint8Array): StatusReport;
export function encodeDoc(value: Doc): Uint8Array;
export function encodeStatusReport(value: StatusReport): Uint8Array;
export function encodeOrphan(value: Doc): Uint8Array;
