# TypeScript library for encrypted IDs

## Motivation

Applications often need to present IDs to users or other applications to refer to concrete resources. For example, an API might provide a user a path like `http://api.example/foo/123e4567-e89b-12d3-a456-426655440000` to fetch a resource of type `foo` named `123e4567-e89b-12d3-a456-426655440000`.

However, doing so may open the application up to enumeration and other timing attacks. Mitigating these attacks can be difficult, especially if one has little control over the whole process (e.g., how the backend database looks up IDs).

## Solution

This no-dependency library uses AES-GCM, a symmetric AEAD cypher, to provide stable IDs that are unique to the application generating them and thus cannot be generated or guessed by users. These opaque IDs neutralise enumeration attacks.

An ID like `123e4567-e89b-12d3-a456-426655440000` is converted to something like `5DkIrKPTmkFPDs4fyI2VTLH1gBGihiKRx4-THjEIwYDmT-Yz`.

Using these IDs incurs in an overhead of about 26.67 bytes for the IV and that authentication tag, plus an overhead of about 33.3% for the binary representation of the ID.

Only UUIDs are implemented, although it is possible to use this library for other types of ID. Since UUIDs can be compactly represented in 16 bytes, this means that a 36-byte UUID (text representation) will result in a 48-byte after being run through this library.

## How to use

### Overview: before use

First, generate a unique and strong secret key for your application (a 16-byte random string should suffice). This will be used to generate and validate IDs, so it is important that this value remain secret.

Before transmitting the internal representation of an ID to a user or another system, call the *encrypt* method. When receiving an ID from a user, call the *decrypt* method to recover the internal representation.

Below there are more concrete examples of these steps.

### Installing

```sh
npm i -D '@exact-realty/safeid'
```

### Getting started

#### Importing the module

In the file you have your configuration, first import this plugin

```js
const { SEncryptId, SDecryptId, UuidSafeId } = require('@exact-realty/safeid');
```

Or using ES module syntax:

```js
import { SEncryptId, SDecryptId, UuidSafeId } from '@exact-realty/safeid';
```

#### Initialising an instance

A secret key is required to encrypt and decrypt IDs.

```js
const key = Buffer.from('TEST KEY - USE YOUR OWN KEY HERE');
```

Then, generate a `UuidSafeId` instance

```js
const safeUuid = await UuidSafeId(key);
```

To encrypt an ID (to provide to an external system):

```js
// This will be an internal ID to protect
const id = 'ffffffff-ffff-4fff-afff-ffffffffffff';
const encrypted = await safeUuid[SEncryptId](id);
// At this point, `encrypted` might contain a string like '0fmlbuVpXDQfKZE16S3paq6ttYp-w7F57v9iq6dRzvLdDeZN'
```

Then, to recover the internal representation:

```js
// Note that this promise may reject if the ID doesn't pass validation
const decrypted = await safeUuid[SDecryptId](encrypted);
// At this point, `decrypted` will contain the internal ID representation, like 'ffffffff-ffff-4fff-afff-ffffffffffff'.
```

### Advanced usage

Although only UUIDs are supported out of the box, it is possible to define custom ID types. This is done by calling the `setup` method with an object that defines a few helpers for encoding and decoding.

See the following example (TypeScript) for a custom ID type that consists of a 6-digit to 8-digit number:

```ts
import type { TIdHelper } from '@exact-realty/safeid';
import {
	SFromBuffer,
	setup,
	SToBuffer,
	SValidByteLengthRange,
} from './genericSafeId';

const idRegex = /^[0-9]{6,8}$/;

const helper: TIdHelper = {
	// Lower and upper bound for ID length (optional)
	[SValidByteLengthRange]: [6, 8],
	// Convert a string to a buffer for encoding (for encryption)
	[SToBuffer]: (clearId: string) => {
		if (!idRegex.test(clearId)) {
			throw new Error('Invalid ID format (expected number of 6 to 8 digits)');
		}

		// ID is stored as an encoded string. Using another representation will be more efficient
		const binaryId = new TextEncoder().encode(clearId);
 
		return binaryId.buffer;
	},
	// Convert a buffer to a string for decoding (for decryption)
	[SFromBuffer]: (buffer: ArrayBuffer) => {
		// Sanity check: is the length what we expect?
		if (buffer.byteLength < 6 || buffer.byteLength > 8) {
			throw new Error(
				'Invalid raw ID after decryption (invalid length)',
			);
		}

		// Decode the byte-encodeed ID to a string
		const id = new TextDecoder().decode(buffer);

		// Sanity check: is this a valid ID?
		if (!idRegex.test(id)) {
			throw new Error('Invalid ID after decryption');
		}

		return id;
	},
};

// Export this module to be used in our application
export const NumericIdSafeId = setup(helper);
```
