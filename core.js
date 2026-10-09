export class LPCore {
	// This pretty much needs all permanent settings.
	/**
	 * Creates an instance of LPCore.
	 *
	 * @constructor
	 * @param {string} staticSecret
	 * @param {string} charset
	 */
	constructor(staticSecret, charset) {
		this.charset = charset;
		this.staticSecret = staticSecret;
	};

	// Main functionallity
	/**
	 * Generates a password based on the given parameters.
	 *
	 * @async
	 * @param {string} siteURL
	 * @param {string} login
	 * @param {string} masterPassword
	 * @param {number} passwordIndex
	 * @param {number} passwordLength
	 * @param {boolean} includeLowerCase
	 * @param {boolean} includeUpperCase
	 * @param {boolean} includeNumbers
	 * @param {boolean} includeSymbols
	 * @returns {string}
	 */
	async getPW(siteURL,login,masterPassword, passwordIndex, passwordLength,
				includeLowerCase, includeUpperCase, includeNumbers, includeSymbols) {

		// TODO - Change once i need a feedback system for errors, for now just return an empty string if the length is invalid
		if (passwordLength < 1) {
			return "";
		}

		if (!includeLowerCase && !includeUpperCase && !includeNumbers && !includeSymbols) {
			return "";
		}

		let charset

		// If any of the filters are on we gotta adjust the char set
		if (!includeLowerCase || !includeUpperCase || !includeNumbers || !includeSymbols) {
			charset = modifyCharset(this.charset, includeLowerCase, includeUpperCase, includeNumbers, includeSymbols)
		} else {
			charset = this.charset
		}

		// - Generate the actual password
		let password = await _generatePassword(siteURL, login, masterPassword, passwordIndex, passwordLength, charset, this.staticSecret)

		// Depending on the filters applied, we gotta hit a target number of categories being represented in the password
		let categoriesWanted = 0

		if (includeLowerCase) {categoriesWanted += 1}
		if (includeUpperCase) {categoriesWanted += 1}
		if (includeNumbers) {categoriesWanted += 1}
		if (includeSymbols) {categoriesWanted += 1}

		// TODO | gotta give some feedback in some way that this isnt possible with under 4 chars if all are enabled
		if (password.length >= categoriesWanted) {
			password = ensureCharCategories(categoriesWanted, charset, password, includeLowerCase, includeUpperCase, includeNumbers, includeSymbols)
		}

		return password
	};

	/**
	 * Used to give the user visible feedback about a hidden password field
	 *
	 * @param {string} masterPassword
	 * @returns {Array<string>}
	 */
	getPassMojis(masterPassword) {
	if (masterPassword.length > 0) {
		const emojis = [
			"🍒","🚽","🌊","🐶","👍","🐀","🌴","🍌",
			"🍏","🔒","🍓","🎓","🎉","🐐","🔥","✋",
			"🤡","🤛","🐈","🚁","🔆","🌜","🔑","🎻",
			"🚧","🏓","🎮","💜","💩","👽","👻","💀",
			"🐱‍👤","🦄","🐍","🐉","🦖","🐘","🦞","🦴",
			"🦷","👀","👅","🦾","🦿","🧠","✨","🎉",
			"💍","💎","🛒","🏆","🥇","🔊","🔧","📞",
			"💣","🔍","📌","🍗","🍇","🥕","🚲","🚀"
		];

		const hash = masterPassword.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0);
		const emoji1 = emojis[hash % emojis.length];
		const emoji2 = emojis[(hash * 2) % emojis.length];
		const emoji3 = emojis[(hash * 3) % emojis.length];

		return [emoji1, emoji2, emoji3]
		}
	};

	/**
	 * Generates a HOTP Code according to the RFC 4226 standard.
	 *
	 * @async
	 * @param {string} secret
	 * @param {number} counter
	 * @param {number} [digits=6]
	 * @param {string} [algorithm="SHA-1"]
	 * @returns {string}
	 */
	async getHOTP(secret,counter,digits = 6,algorithm = "SHA-1") {
		const secretBytes = base32Decode(secret);
		// 8-byte big-endian counter
		const counterBuffer = new ArrayBuffer(8);
		const view = new DataView(counterBuffer);
		const high = Math.floor(counter / 0x100000000);
		const low = counter >>> 0;
		view.setUint32(0, high, false);
		view.setUint32(4, low, false);
		const key = await crypto.subtle.importKey(
			"raw",
			secretBytes,
			{
				name: "HMAC",
				hash: algorithm
			},
			false,
			["sign"]
		);

		const hmac = await crypto.subtle.sign(
			"HMAC",
			key,
			counterBuffer
		);
		const hash = new Uint8Array(hmac);
		const offset = hash[hash.length - 1] & 0x0f;
		const binary =
			((hash[offset] & 0x7f) << 24) |
			((hash[offset + 1] & 0xff) << 16) |
			((hash[offset + 2] & 0xff) << 8) |
			(hash[offset + 3] & 0xff);
		const otp = binary % (10 ** digits);
		return otp.toString().padStart(digits, "0");
	}

	/**
	 * Generates a TOTP Code according to the RFC 6238 standard.
	 *
	 * @async
	 * @param {string} secret
	 * @param {number} [digits=6]
	 * @param {string} [algorithm="SHA-1"]
	 * @param {number} [period=30]
	 * @param {number} [timestamp=Date.now()]
	 * @returns {string}
	 */
	async getTOTP(
		secret,
		digits = 6,
		algorithm = "SHA-1",
		period = 30,
		timestamp = Date.now()
	) {
		const counter = Math.floor(timestamp / 1000 / period);

		return await this.getHOTP(
			secret,
			counter,
			digits,
			algorithm
		);
	}
};

function modifyCharset(charset, includeLowerCase, includeUpperCase, includeNumbers, includeSymbols) {
	if (!includeLowerCase) {charset = charset.replace(/[a-z]/g, "");}
	if (!includeUpperCase) {charset = charset.replace(/[A-Z]/g, "");}
	if (!includeNumbers) {charset = charset.replace(/[0-9]/g, "");}
	if (!includeSymbols) {charset = charset.replace(/[^a-zA-Z0-9]/g, "");}
	return charset
};

async function _generatePassword(siteURL,login,masterPassword,passwordIndex,passwordLength,charset,staticSecret) {
		// This function assumes that all the inputs are fine in terms of filters and what not
		const encoder = new TextEncoder();
		const userInputSalt = encoder.encode(siteURL + staticSecret + passwordIndex + login);

		const keyMaterial = await globalThis.crypto.subtle.importKey(
			"raw", encoder.encode(masterPassword), { name: "PBKDF2" }, false, ["deriveBits"]
		);

		const derivedBits = await globalThis.crypto.subtle.deriveBits(
			{ name: "PBKDF2", salt: userInputSalt, iterations: 300000, hash: "SHA-256" }, keyMaterial, passwordLength * 8
		);

		const hashArray = Array.from(new Uint8Array(derivedBits));

		return Array.from({ length: passwordLength }, (_, i) =>
				charset[(hashArray[i] + hashArray[(i + passwordLength) % hashArray.length]) % charset.length]
			).join('');
	}

function ensureCharCategories(categoriesWanted, charset, password, includeLowerCase, includeUpperCase, includeNumbers, includeSymbols) {
	let validatedRules = 0
	while (validatedRules < categoriesWanted) {

		// Reset the count everytime we check the password
		validatedRules = 0

		// We get a list of chars used per category in the current password, so that we know what to replace later
		let usedLowerCase = password.match(/[a-z]/g)
		let usedUpperCase = password.match(/[A-Z]/g)
		let usedNumbers = password.match(/[0-9]/g)
		let usedSymbols = password.match(/[^a-zA-Z0-9]/g)

		// If lowers are enalbed BUT there are none used
		if (includeLowerCase && (!usedLowerCase || usedLowerCase.length === 0)) {
			// -> fill the password, with a lowercase char from charset by replacing one from the most used categories
			password = injectCharIntoPassword(password,charset.match(/[a-z]/g), usedUpperCase, usedNumbers, usedSymbols)
			// I could declare the rule as validated here but there could be an edge case where a later
			// rule screws over this rule again in some way so ill instead do 1 more run instead
		} else {
			validatedRules += 1
		}

		// Uppercase
		if (includeUpperCase && (!usedUpperCase || usedUpperCase.length === 0)) {
			// -> fill the password, with a CAPS from charset by replacing one from the most used categories (which is why we pass used*)
			password = injectCharIntoPassword(password,charset.match(/[A-Z]/g), usedLowerCase, usedNumbers, usedSymbols)
		} else {
			validatedRules += 1
		}

		// Numbers
		if (includeNumbers && (!usedNumbers || usedNumbers.length === 0)) {
			// -> fill the password, with a number from charset by replacing one from the most used categories
			password = injectCharIntoPassword(password,charset.match(/[0-9]/g), usedUpperCase, usedLowerCase, usedSymbols)
		} else {
			validatedRules += 1
		}

		// Symbols
		if (includeSymbols && (!usedSymbols || usedSymbols.length === 0)) {
			// -> fill the password, with a symbol from charset by replacing one from the most used categories
			password = injectCharIntoPassword(password,charset.match(/[^a-zA-Z0-9]/g), usedUpperCase, usedNumbers, usedLowerCase)
		} else {
			validatedRules += 1
		}
	}
	return password
}

function injectCharIntoPassword(password, charSubSet, ...usedCategories) {
	// Doing a bunch of stuff to make this replacement deterministic

	// seed based on the current password
	let seed = 0;
	for (let i = 0; i < password.length; i++) {
		seed = (seed * 31 + password.charCodeAt(i) + i) >>> 0;
	}

	// xorshift
	const deterRand = () => {
		seed = (seed * 1664525 + 1013904223) >>> 0;
		return seed;
	};

	// Find the category with the most used chars that also has at least 2 used chars
	let maxCategory = null;
	let maxCount = 1; // need at least 2 to be able to replace one
	for (const category of usedCategories) {
		if (category && category.length > maxCount) {
			maxCount = category.length;
			maxCategory = category;
		}
	}

	if (maxCategory) {
		// choose a deterministic element from the maxCategory
		const idxInCategory = deterRand() % maxCategory.length;
		const charToReplace = maxCategory[idxInCategory];

		// find all occurrences of that char in the password
		const occurrences = [];
		for (let i = 0; i < password.length; i++) {
			if (password[i] === charToReplace) occurrences.push(i);
		}

		if (occurrences.length > 0) {
			// pick a deterministic occurrence to replace
			const occIndex = deterRand() % occurrences.length;
			const charIndex = occurrences[occIndex];

			// pick a deterministic char to insert from availableChars
			const charToInsert = charSubSet[deterRand() % charSubSet.length];

			password = password.substring(0, charIndex) + charToInsert + password.substring(charIndex + 1);
		}
	}
	return password;
}


// --- 2FA

function base32Decode(input) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	input = input
		.replace(/=+$/, "")
		.replace(/\s+/g, "")
		.toUpperCase();

	let bits = "";
	for (const c of input) {
		const value = alphabet.indexOf(c);
		if (value === -1)
			throw new Error("Invalid Base32");
		bits += value.toString(2).padStart(5, "0");
	}

	const bytes = [];
	for (let i = 0; i + 8 <= bits.length; i += 8)
		bytes.push(parseInt(bits.substring(i, i + 8), 2));
	return new Uint8Array(bytes);
}