/*
 * Copyright (c) 2016, 2017, 2018 U&A Services UG
 */
var cryptojsutilswrapper = (function () {
	var toBase64String = function(i) {
		return CryptoJS.enc.Base64.stringify(i);
	};
	
	return {
		/*
		 * Encrypts the specified text. 
		 * Returns an object containing the generated 
		 * IV, Salt and encrypted content.
		 */
		encrypt: function (secret, plainText) {
			var encryptorOptions = cryptojsutils.createEncryptorOptions(secret);
			var encryptedChunks = cryptojsutils.encryptChunks(encryptorOptions, [ plainText ]);
			var result = {
				iv: toBase64String(encryptorOptions.IV),
				salt: toBase64String(encryptorOptions.Salt),
				content: encryptedChunks[0]
			};
			return result;
		},
		/*
		 * Encrypts the specified id and text using the same secret (and salt and iv).
		 * Returns an object that can be directly passed to the API POST create method.
		 * { Id, Tag, Salt, IV, Content, SID }
		 */
		 encryptForCreate: function (secret, plainText, tag, id) {
			 return cryptojsutils.encrypt(id, tag, secret, plainText);
		 },
		/*
		 * Decrypts the specified encrypted text. 
		 * Returns a string object holding the content as plain text.
		 */
		decrypt: function (secret, encryptedText, salt, iv) {
			var decryptorOptions = cryptojsutils.createDecryptorOptions(secret, salt, iv);
			var result = cryptojsutils.decryptChunks(decryptorOptions, [ encryptedText ]);
			return result[0];
		}
	}
}());
