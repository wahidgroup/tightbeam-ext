/* tslint:disable */
/* eslint-disable */
export interface Doc {
    title: string;
}

export interface StatusReport {
    status: number;
}

export function decodeDoc(bytes: Uint8Array): any;
export function decodeStatusReport(bytes: Uint8Array): any;
export function encodeDoc(value: any): Uint8Array;
export function encodeStatusReport(value: any): Uint8Array;
export function encodeOrphan(value: any): Uint8Array;
