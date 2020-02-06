/*
 * Copyright (c) 2016, 2017, 2018 U&A Services UG
 */
var cryptojsutils = (function () {
    // 
    var DERIVE_BYTES_ITERATIONS = 1000;
    var ENCRYPTION_ALGORITHM_KEY_BITS = 128;
    var ENCRYPTION_ALGORITHM_KEY_BYTES = ENCRYPTION_ALGORITHM_KEY_BITS / 8;
    var ENCRYPTION_ALGORITHM_KEY_SIZE = ENCRYPTION_ALGORITHM_KEY_BITS / 32;
    //
    return {
        createEncryptorOptions: function (secret) {
            var result = { Salt: "", IV: "", Key: "" };
            try {
                var secretp = CryptoJS.enc.Utf8.parse(secret);
                var iv = CryptoJS.lib.WordArray.random(ENCRYPTION_ALGORITHM_KEY_BYTES);
                var salt = CryptoJS.lib.WordArray.random(ENCRYPTION_ALGORITHM_KEY_BYTES);
                var key128Bits1000Iterations = CryptoJS.PBKDF2(secretp.toString(CryptoJS.enc.Utf8), salt,
                    {
                        keySize: ENCRYPTION_ALGORITHM_KEY_SIZE,
                        iterations: DERIVE_BYTES_ITERATIONS
                    });
                result = {
                    Salt: salt,
                    IV: iv,
                    Key: key128Bits1000Iterations
                };
            } catch (e) {
                result = { Salt: "", IV: "", Key: "" };
            }
            return result;
        }
        , //
        encryptChunks: function (encryptorOptions, plainChunks) {
            var encryptedChunks = [];
            plainChunks.forEach(function (plainChunk) {
                var ec = CryptoJS.AES.encrypt(plainChunk, encryptorOptions.Key,
                {
                    mode: CryptoJS.mode.CBC,
                    iv: encryptorOptions.IV,
                    padding: CryptoJS.pad.Pkcs7
                }).ciphertext.toString(CryptoJS.enc.Base64);
                encryptedChunks.push(ec);
            });
            return encryptedChunks;
        }
        , //
        encryptWithOptions: function (id, tag, options, input, fileInfo) {
            var result = { id: "", Salt: "", IV: "", Note: "" };
            try {
                var iv = options.IV;
                var salt = options.Salt;
                var key128Bits1000Iterations = options.Key;
                var encryptedSid = CryptoJS.AES.encrypt(id, key128Bits1000Iterations,
                    {
                        mode: CryptoJS.mode.CBC,
                        iv: iv,
                        padding: CryptoJS.pad.Pkcs7
                    });
                var content = input.join('|');
                var sid = encryptedSid.ciphertext.toString(CryptoJS.enc.Base64);
                result = {
                    Id: id,
                    Tag: tag,
                    Salt: CryptoJS.enc.Base64.stringify(salt),
                    IV: CryptoJS.enc.Base64.stringify(iv),
                    Content: content.toString(),
                    SID: sid
                };
                if (fileInfo) {
                    result.FileName = fileInfo.name;
                    result.FileMimeType = fileInfo.mimeType;
                }
            } catch (e) {
                result = { Id: "", Tag: "", Salt: "", IV: "", Content: "", SID: "" };
            }
            return result;
        }
        , //
        createDecryptorOptions: function (secret, salt, iv) {
            var result = { IV: "", Key: "" };
            try {
                var secretp = CryptoJS.enc.Utf8.parse(secret);
                var ivp = CryptoJS.enc.Base64.parse(iv);
                var saltp = CryptoJS.enc.Base64.parse(salt);
                var key128Bits1000Iterations = CryptoJS.PBKDF2(secretp.toString(CryptoJS.enc.Utf8), saltp,
                    {
                        keySize: ENCRYPTION_ALGORITHM_KEY_SIZE,
                        iterations: DERIVE_BYTES_ITERATIONS
                    });
                result = {
                    IV: ivp,
                    Key: key128Bits1000Iterations
                };
            } catch (e) {
                result = { IV: "", Key: "" };
            }
            return result;
        }
        , //
        decryptChunks: function (decryptorOptions, encryptedChunks) {
            var plainChunks = [];
            encryptedChunks.forEach(function (encryptedChunk) {
                var cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse(encryptedChunk) });
                var dc = CryptoJS.AES.decrypt(cipherParams, decryptorOptions.Key,
                    {
                        mode: CryptoJS.mode.CBC,
                        iv: decryptorOptions.IV,
                        padding: CryptoJS.pad.Pkcs7
                    });
                plainChunks.push(dc.toString(CryptoJS.enc.Utf8));
            });
            return plainChunks;
        }
        , //
        decrypt: function (secret, salt, iv, input) {
            var result = "";
            try {
                var secretp = CryptoJS.enc.Utf8.parse(secret);
                var ivp = CryptoJS.enc.Base64.parse(iv);
                var saltp = CryptoJS.enc.Base64.parse(salt);
                var key128Bits1000Iterations = CryptoJS.PBKDF2(secretp.toString(CryptoJS.enc.Utf8), saltp,
                    {
                        keySize: ENCRYPTION_ALGORITHM_KEY_SIZE,
                        iterations: DERIVE_BYTES_ITERATIONS
                    });
                var cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse(input) });
                var decrypted = CryptoJS.AES.decrypt(cipherParams, key128Bits1000Iterations,
                    {
                        mode: CryptoJS.mode.CBC,
                        iv: ivp,
                        padding: CryptoJS.pad.Pkcs7
                    });
                result = decrypted.toString(CryptoJS.enc.Utf8);
            } catch (e) {
                result = "";
            }
            return result;
        }
        , // 
        encrypt: function (id, tag, secret, input, expire) {
            var result = { id: "", Salt: "", IV: "", Note: "" };
            try {
                var secretp = CryptoJS.enc.Utf8.parse(secret);
                var iv = CryptoJS.lib.WordArray.random(ENCRYPTION_ALGORITHM_KEY_BYTES);
                var salt = CryptoJS.lib.WordArray.random(ENCRYPTION_ALGORITHM_KEY_BYTES);
                var key128Bits1000Iterations = CryptoJS.PBKDF2(secretp.toString(CryptoJS.enc.Utf8), salt,
                    {
                        keySize: ENCRYPTION_ALGORITHM_KEY_SIZE,
                        iterations: DERIVE_BYTES_ITERATIONS
                    });
                var encrypted = CryptoJS.AES.encrypt(input, key128Bits1000Iterations,
                    {
                        mode: CryptoJS.mode.CBC,
                        iv: iv,
                        padding: CryptoJS.pad.Pkcs7
                    });
                var encryptedSid = CryptoJS.AES.encrypt(id, key128Bits1000Iterations,
                    {
                        mode: CryptoJS.mode.CBC,
                        iv: iv,
                        padding: CryptoJS.pad.Pkcs7
                    });
                var content = encrypted.ciphertext.toString(CryptoJS.enc.Base64);
                var sid = encryptedSid.ciphertext.toString(CryptoJS.enc.Base64);
                result = {
                    Id: id,
                    Tag: tag,
                    Salt: CryptoJS.enc.Base64.stringify(salt),
                    IV: CryptoJS.enc.Base64.stringify(iv),
                    Content: content.toString(),
                    SID: sid
                };
                if (expire) {
                    result.ExpirationDate = moment().format();
                }
            } catch (e) {
                result = { Id: "", Tag: "", Salt: "", IV: "", Content: "", SID: "" };
            }
            return result;
        }
    }
}());