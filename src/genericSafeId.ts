/* Copyright © 2023 Exact Realty Limited.
 *
 * All rights reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

// ID encryption and decryption
// ID is not sensitive, but the values are encrypted to
// prevent enumeration attacks through leaked timing information
// when doing lookups.
// Authenticated encryption *must* be used because it's the
// authentication, not the encryption, that prevents these attacks.

export const SToBuffer = Symbol();
export const SValidByteLengthRange = Symbol();
export const SFromBuffer = Symbol();
export const SEncryptId = Symbol();
export const SDecryptId = Symbol();

export type TIdHelper = {
	[SValidByteLengthRange]?: [number, number];
	[SToBuffer]: { (id: string): ArrayBuffer };
	[SFromBuffer]: { (buffer: ArrayBuffer): string };
};

export type TSafeId = {
	[SEncryptId]: { (id: string): Promise<string> };
	[SDecryptId]: { (id: string): Promise<string> };
};

const HKDF_INFO_HMAC = 'safeid#sign';
const HKDF_INFO_ENCRYPTION = 'safeid#encrypt';

const btoau = (data: string | Uint8Array) => {
	if (data instanceof Uint8Array) {
		data = String.fromCharCode.apply(null, Array.from(data));
	}

	return btoa(data)
		.replace(/=+$/g, '')
		.split('+')
		.join('-')
		.split('/')
		.join('_');
};

const autob = (data: string | Uint8Array) => {
	if (data instanceof Uint8Array) {
		data = String.fromCharCode.apply(null, Array.from(data));
	}

	return atob(data.split('-').join('+').split('_').join('/'));
};

export const setup: {
	(helper: TIdHelper): {
		(secretHkdfBaseKey: ArrayBuffer): Promise<TSafeId>;
	};
} = (helper) => async (secretHkdfBaseKey) => {
	const baseKey: CryptoKey = await globalThis.crypto.subtle.importKey(
		'raw',
		secretHkdfBaseKey,
		'HKDF',
		false,
		['deriveKey'],
	);

	const textEncoder = new TextEncoder();

	const signKey = await globalThis.crypto.subtle.deriveKey(
		{
			['name']: 'HKDF',
			['hash']: 'SHA-256',
			['salt']: new Uint8Array(0),
			['info']: textEncoder.encode(HKDF_INFO_HMAC),
		},
		baseKey,
		{
			['name']: 'HMAC',
			['hash']: 'SHA-256',
			['length']: 256,
		},
		false,
		['sign'],
	);

	const encodedInfoEncKey = textEncoder.encode(HKDF_INFO_ENCRYPTION);

	const encryptId = async (clearId: string): Promise<string> => {
		const buffer = helper[SToBuffer](clearId);

		// The IV is derived from the buffer itself to produce stable IDs
		const iv = new Uint8Array(
			await globalThis.crypto.subtle.sign(
				{ ['name']: 'HMAC' },
				signKey,
				buffer,
			),
			0,
			12,
		);

		const encryptionKey = await globalThis.crypto.subtle.deriveKey(
			{
				['name']: 'HKDF',
				['hash']: 'SHA-256',
				['salt']: iv,
				['info']: encodedInfoEncKey,
			},
			baseKey,
			{
				['name']: 'AES-GCM',
				['length']: 256,
			},
			false,
			['encrypt'],
		);

		const ciphertext = new Uint8Array(
			await globalThis.crypto.subtle.encrypt(
				{ ['name']: 'AES-GCM', ['iv']: iv, ['tagLength']: 64 },
				encryptionKey,
				buffer,
			),
		);

		const result = new Uint8Array(iv.byteLength + ciphertext.byteLength);

		result.set(iv, 0);
		result.set(ciphertext, iv.byteLength);

		return btoau(result);
	};

	const decryptId = async (encryptedUuid: string): Promise<string> => {
		const validByteLengthRange = (
			(Array.isArray(helper[SValidByteLengthRange]) &&
				helper[SValidByteLengthRange]?.length === 2 &&
				helper[SValidByteLengthRange]) || [0, Number.POSITIVE_INFINITY]
		).map((v) => Math.ceil(((v + 12 + 8) * 8) / 6));

		if (
			encryptedUuid.length < validByteLengthRange[0] ||
			encryptedUuid.length > validByteLengthRange[1] ||
			!/^[a-zA-Z0-9_-]+$/.test(encryptedUuid)
		) {
			throw new Error('Invalid encrypted ID');
		}

		const buffer = new Uint8Array(
			autob(encryptedUuid)
				.split('')
				.map((b) => b.charCodeAt(0)),
		);

		const iv = buffer.subarray(0, 12);
		const ciphertext = buffer.subarray(12);

		const decryptionKey = await globalThis.crypto.subtle.deriveKey(
			{
				['name']: 'HKDF',
				['hash']: 'SHA-256',
				['salt']: iv,
				['info']: encodedInfoEncKey,
			},
			baseKey,
			{
				['name']: 'AES-GCM',
				['length']: 256,
			},
			false,
			['decrypt'],
		);

		const plaintext = await globalThis.crypto.subtle.decrypt(
			{ ['name']: 'AES-GCM', ['iv']: iv, ['tagLength']: 64 },
			decryptionKey,
			ciphertext,
		);

		const expectedIv = new Uint8Array(
			await globalThis.crypto.subtle.sign(
				{ ['name']: 'HMAC' },
				signKey,
				plaintext,
			),
			0,
			iv.byteLength,
		);

		const ivEqualsExpectedIv =
			iv
				.map((v, i) => v ^ expectedIv[i])
				.reduce((acc, cv) => acc | cv, 0) === 0;

		if (!ivEqualsExpectedIv) {
			throw new Error(
				'Raw ID after decryption does not produce the expected IV',
			);
		}

		return helper[SFromBuffer](plaintext);
	};

	return { [SEncryptId]: encryptId, [SDecryptId]: decryptId };
};
3;
