/* Copyright © 2023 Exact Realty Limited.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

import { webcrypto } from 'node:crypto';

import * as m from '../src';

import assert from 'node:assert/strict';

!globalThis.crypto &&
	((() => globalThis || { crypto: {} })().crypto =
		webcrypto as unknown as Crypto);

const testUuids = (key: ArrayBuffer, ids: string[]) => async () => {
	const f = await m.UuidSafeId(key);

	const encrypted = await Promise.all(ids.map((id) => f[m.SEncryptId](id)));

	const decrypted = await Promise.all(
		encrypted.map((eid) => f[m.SDecryptId](eid)),
	);

	for (const id of ids.entries()) {
		assert.strictEqual(
			id[1],
			decrypted[id[0]],
			'decrypted ID should match original value',
		);
	}
};

describe('Safe IDs', () => {
	describe('Base key', () => {
		it('should generate different IDs for different secret keys', async () => {
			const f1 = await m.UuidSafeId(new Uint8Array(1));
			const f2 = await m.UuidSafeId(new Uint8Array(1));
			const g = await m.UuidSafeId(new Uint8Array(2));

			const encrypted = await Promise.all([
				f1[m.SEncryptId]('00000000-0000-4000-8000-000000000000'),
				f2[m.SEncryptId]('00000000-0000-4000-8000-000000000000'),
				g[m.SEncryptId]('00000000-0000-4000-8000-000000000000'),
			]);

			assert.strictEqual(
				encrypted[0],
				encrypted[1],
				'the same base key should result in the same encrypted id',
			);
			assert.notEqual(
				encrypted[0],
				encrypted[2],
				'a different key should result in a different encrypted id',
			);

			assert.rejects(
				f1[m.SDecryptId](encrypted[2]),
				'a different instance with the same base key should not decrypt IDs',
			);
			assert.doesNotReject(
				f1[m.SDecryptId](encrypted[1]),
				'a different instance with the same base key should decrypt IDs',
			);
		});
	});

	describe('Encryption and decription', () => {
		it(
			'Static test vectors can be encrypted and decrypted (static key)',
			testUuids(new Uint8Array(8), [
				'00000000-0000-0000-0000-000000000000',
				'00000000-0000-4000-8000-000000000000',
				'123e4567-e89b-12d3-a456-426655440000',
				'00112233-4455-4677-8899-aabbccddeeff',
				'96e17d7a-ac89-38cf-95e1-bf5098da34e1',
				'e8b764da-5fe5-51ed-8af8-c5c6eca28d7a',
				'c232ab00-9414-11ec-b3c8-9e6bdeced846',
				'1ec9414c-232a-6b00-b3c8-9e6bdeced846',
				'017f22e2-79b0-7cc3-98c4-dc0c0c07398f',
				'320c3d4d-cc00-875b-8ec9-32d5f69181c0',
			]),
		);

		it(
			'Static test vectors can be encrypted and decrypted (random key)',
			testUuids(globalThis.crypto.getRandomValues(new Uint8Array(16)), [
				'00000000-0000-0000-0000-000000000000',
				'00000000-0000-4000-8000-000000000000',
				'123e4567-e89b-12d3-a456-426655440000',
				'00112233-4455-4677-8899-aabbccddeeff',
				'96e17d7a-ac89-38cf-95e1-bf5098da34e1',
				'e8b764da-5fe5-51ed-8af8-c5c6eca28d7a',
				'c232ab00-9414-11ec-b3c8-9e6bdeced846',
				'1ec9414c-232a-6b00-b3c8-9e6bdeced846',
				'017f22e2-79b0-7cc3-98c4-dc0c0c07398f',
				'320c3d4d-cc00-875b-8ec9-32d5f69181c0',
			]),
		);

		it(
			'Random UUIDs can be encrypted and decrypted (static key)',
			testUuids(
				new Uint8Array(8),
				new Array(64)
					.fill(undefined)
					.map(() => globalThis.crypto.randomUUID()),
			),
		);

		it(
			'Random UUIDs can be encrypted and decrypted (random key)',
			testUuids(
				globalThis.crypto.getRandomValues(new Uint8Array(16)),
				new Array(64)
					.fill(undefined)
					.map(() => globalThis.crypto.randomUUID()),
			),
		);
	});
});
