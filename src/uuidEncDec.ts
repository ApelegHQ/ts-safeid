/* Copyright © 2023 Apeleg Limited.
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

import type { TIdHelper } from './genericSafeId.js';
import {
	SFromBuffer,
	SToBuffer,
	SValidByteLengthRange,
	setup,
} from './genericSafeId.js';

const uuidRegex =
	/^(?:00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff|[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;

const textDecoder = new TextDecoder('us-ascii', {
	['fatal']: true,
	['ignoreBOM']: true,
});

const helper: TIdHelper = {
	[SValidByteLengthRange]: [16, 16],
	[SToBuffer]: (clearUuid: string) => {
		if (!uuidRegex.test(clearUuid)) {
			throw new Error('Invalid ID format (expected UUID)');
		}

		const binaryUuid = Uint32Array.from(
			[
				clearUuid.substring(0, 8),
				clearUuid.substring(9, 13) + clearUuid.substring(14, 18),
				clearUuid.substring(19, 23) + clearUuid.substring(24, 28),
				clearUuid.substring(28, 36),
			],
			(v) => parseInt(v, 16),
		);

		return binaryUuid.buffer;
	},
	[SFromBuffer]: (buffer: ArrayBuffer) => {
		if (buffer.byteLength !== 16) {
			throw new Error(
				'Invalid raw UUID after decryption (invalid length)',
			);
		}

		const data = new Uint32Array(buffer);
		const t = new Uint8Array(8);
		const uuidA = new Uint8Array(36);

		for (let i = 0; i !== data.length; i++) {
			for (let j = 0; j !== t.length; j++) {
				t[j] = (data[i] >> ((7 - j) << 2)) & 0xf;
				t[j] = (t[j] | 0x30) + (t[j] > 9 ? 39 : 0);
			}
			uuidA.set(t, i * 8);
		}

		uuidA.copyWithin(36 - 12, 32 - 12, 32);
		uuidA.copyWithin(36 - 12 - 1 - 4, 32 - 12 - 4, 32 - 12);
		uuidA.copyWithin(36 - 12 - 1 - 4 - 1 - 4, 32 - 12 - 4 - 4, 32 - 12 - 4);
		uuidA.copyWithin(
			36 - 12 - 1 - 4 - 1 - 4 - 1 - 4,
			32 - 12 - 4 - 4 - 4,
			32 - 12 - 4 - 4,
		);

		// Set dashes ('-')
		uuidA[8] = uuidA[8 + 1 + 4] = uuidA[8 + 2 + 8] = uuidA[8 + 3 + 12] = 45;

		const uuid = textDecoder.decode(uuidA);

		if (!uuidRegex.test(uuid)) {
			throw new Error('Invalid UUID after decryption');
		}

		return uuid;
	},
};

export const UuidSafeId = setup(helper);
