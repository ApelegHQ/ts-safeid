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

import type { TIdHelper } from './genericSafeId';
import {
	SFromBuffer,
	setup,
	SToBuffer,
	SValidByteLengthRange,
} from './genericSafeId';

const uuidRegex =
	/^(?:00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff|[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;

const helper: TIdHelper = {
	[SValidByteLengthRange]: [16, 16],
	[SToBuffer]: (clearUuid: string) => {
		if (!uuidRegex.test(clearUuid)) {
			throw new Error('Invalid ID format (expected UUID)');
		}

		const binaryUuid = new Uint16Array(
			clearUuid
				.replace(/-/g, '')
				.split(/(?=(?:....)*$)/)
				.map((c) => parseInt(c, 16)),
		);

		return binaryUuid.buffer;
	},
	[SFromBuffer]: (buffer: ArrayBuffer) => {
		if (buffer.byteLength !== 16) {
			throw new Error(
				'Invalid raw UUID after decryption (invalid length)',
			);
		}

		const data = new Uint16Array(buffer);

		const uuid = [
			data.subarray(0, 2),
			data.subarray(2, 3),
			data.subarray(3, 4),
			data.subarray(4, 5),
			data.subarray(5, 8),
		]
			.map((v) => {
				const r = new Array(v.length);
				for (let i = 0; i !== v.length; i++) {
					const hi = (v[i] >> 12) & 0xf;
					const mh = (v[i] >> 8) & 0xf;
					const ml = (v[i] >> 4) & 0xf;
					const lo = v[i] & 0xf;
					r[i] = String.fromCharCode(
						(hi | 0x30) + (hi > 9 ? 39 : 0),
						(mh | 0x30) + (mh > 9 ? 39 : 0),
						(ml | 0x30) + (ml > 9 ? 39 : 0),
						(lo | 0x30) + (lo > 9 ? 39 : 0),
					);
				}
				return r.join('');
			})
			.join('-');

		if (!uuidRegex.test(uuid)) {
			throw new Error('Invalid UUID after decryption');
		}

		return uuid;
	},
};

export const UuidSafeId = setup(helper);
