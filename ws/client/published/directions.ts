/**
 * The guarantees of the published declarations, which this project reads through the exports of the package.
 */

import type {
	BodyCompressor,
	BodyDecryptor,
	BodyEncryptor,
	BodyInflator,
	Envelope,
	FrameVerifier,
	Hasher,
	MessageCodec,
	PayloadCodec,
	Signatory,
	TransportSigner,
} from "@wahidgroup/tightbeam-ws-client";

/**
 * Whether `From` widens to `To` in the published declarations.
 */
type Widens<From, To> = [From] extends [To] ? "widens" : "refused";

/**
 * A verify-only envelope holds no send half, so it stays apart from an envelope that sends.
 */
export const verifyOnly: Widens<Envelope<string, false, true>, Envelope<string, true, true>> = "refused";

/**
 * A sign-only envelope holds no receive half, so it stays apart from an envelope that receives.
 */
export const signOnly: Widens<Envelope<string, true, false>, Envelope<string, true, true>> = "refused";

/**
 * An envelope that runs both directions widens to itself.
 */
export const both: Widens<Envelope<string, true, true>, Envelope<string, true, true>> = "widens";

/**
 * `Member` with its first parameter narrowed, as an implementation that admits less than its capability declares.
 */
type NarrowFirst<Member> = Member extends (first: infer First, ...rest: infer Rest) => infer Out
	? (first: First & { readonly narrowed: true }, ...rest: Rest) => Out
	: never;

/**
 * `Capability` with the first parameter of `Member` narrowed.
 */
type Narrowed<Capability, Member extends keyof Capability> = {
	[Key in keyof Capability]: Key extends Member ? NarrowFirst<Capability[Key]> : Capability[Key];
};

/**
 * Whether an implementation that narrows the first parameter of any operation of `Capability` still widens to it.
 */
type Narrowing<Capability> = "widens" extends {
	[Key in keyof Capability]-?: NonNullable<Capability[Key]> extends (...inputs: infer Inputs) => unknown
		? Inputs extends []
			? never
			: Widens<Narrowed<Capability, Key>, Capability>
		: never;
}[keyof Capability]
	? "widens"
	: "refused";

/**
 * An implementation that narrows a parameter of a capability operation stays apart from the capability, so each
 * implementation admits every input the client passes it.
 */
export const narrowed: readonly [
	Narrowing<Hasher>,
	Narrowing<BodyEncryptor>,
	Narrowing<BodyDecryptor>,
	Narrowing<FrameVerifier>,
	Narrowing<Signatory>,
	Narrowing<BodyCompressor>,
	Narrowing<BodyInflator>,
	Narrowing<MessageCodec<string>>,
	Narrowing<PayloadCodec<string>>,
	Narrowing<TransportSigner>,
] = ["refused", "refused", "refused", "refused", "refused", "refused", "refused", "refused", "refused", "refused"];
