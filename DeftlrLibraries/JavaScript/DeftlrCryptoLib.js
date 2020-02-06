/*
 * Copyright (c) 2016, 2017, 2018 U&A Services UG
 *  
 * Deftlr helper module constructor
 * - secret (string): key used for encryption and decryption
 */
function DeftlrCryptoHelper(secret) {
    /* 
     * encrypt(message) -> (object)
     * - message (string): plain text to be encrypted
     * - returns: encrypted item object 
     * 				  { 
     *					 salt,		// encryption salt 
     *					 iv,		// encryption initialization vector 
     *					 content	// encrypted content
     *				   }
     */
    this.encrypt = function (message) {
        return cryptojsutilswrapper.encrypt(secret, message);
    };

    /* 
     * encryptAndStringify(message) -> (stringified object)
     * - message (string): plain text to be encrypted
     * - returns: stringified encrypted item object
     * 				  { 
     *					 salt,		// encryption salt 
     *					 iv,		// encryption initialization vector 
     *					 content	// encrypted content
     *				   }
     */
    this.encryptAndStringify = function (message) {
        return JSON.stringify(this.encrypt(message));
    };

    /*
     * encryptForCreate(id, tag, message) -> (object)
     * - id (string): generated unique entry id
     * - tag (string): unique entry tag
     * - message (string): plain text to be encrypted
     * - returns: encrypted item object
     *					{
     *						Id,
     *						Tag,
     *						Salt,
     *						IV,
     *						Content,
     *						SID
     *					}
     */
    this.encryptForCreate = function (id, tag, message) {
        return cryptojsutilswrapper.encryptForCreate(secret, message, tag, id);
    };

    /*
     * decrypt(encryptedContent, salt, iv) -> (string)
     * - encryptedContent (string): the encrypted content
     * - salt (string): encryption salt
     * - iv (string): encryption initialization vector
     * - returns: decrypted message as plain text
     */
    this.decrypt = function (encryptedContent, salt, iv) {
        return cryptojsutilswrapper.decrypt(secret, encryptedContent, salt, iv);
    };

    /*
     * decryptObject(deftlrObject) -> (string)
     * - deftlrObject (object): encrypted item object {...}
     * - returns: decrypted message as plain text
     */
    this.decryptObject = function (deftlrObject) {
        return this.decrypt(deftlrObject.content, deftlrObject.salt, deftlrObject.iv);
    };

    /*
     * decryptObjectFromString(deftlrObjectAsString) -> (string)
     * - deftlrObject (object): encrypted item object {...}
     * - returns: decrypted message as plain text
     */
    this.decryptObjectFromString = function (deftlrObjectAsString) {
        var deftlrObject = JSON.parse(deftlrObjectAsString);
        return this.decrypt(deftlrObject.content, deftlrObject.salt, deftlrObject.iv);
    };
}

function DeftlrCryptoLib(clientVerificationToken, baseUrl, token) {

    var cryptor = new DeftlrCryptoHelper(token);

    function ajaxGet(method, parameter, doneCallback, failCallback) {
        var m = method;
        if (parameter) {
            m += "/" + parameter;
        }
        $.ajax({
            method: "GET",
            url: baseUrl + m,
            headers: {
                "ClientVerificationToken": clientVerificationToken
            }
        })
        .done(doneCallback)
        .fail(failCallback);
    }

    function ajaxPost(method, data, doneCallback, failCallback) {
        $.ajax({
            method: "POST",
            url: baseUrl + method,
            headers: {
                "ClientVerificationToken": clientVerificationToken
            },
            data: JSON.stringify(data),
            contentType: "application/json"
        })
        .done(doneCallback)
        .fail(failCallback);
    }

    function ajaxDelete(method, parameter, doneCallback, failCallback) {
        var m = method;
        if (parameter) {
            m += "/" + parameter;
        }
        $.ajax({
            method: "DELETE",
            url: baseUrl + m,
            headers: {
                "ClientVerificationToken": clientVerificationToken
            },
            contentType: "application/json"
        })
        .done(doneCallback)
        .fail(failCallback);
    }

    function id(doneCallback, failCallback) {
        ajaxGet("id", null, doneCallback, failCallback);
    }

    function search(tag, doneCallback, failCallback) {
        ajaxGet("search", tag, function (response) {
            if (!response.IsEmpty) {
                var sid = cryptor.decrypt(response.SID, response.Salt, response.IV);
                doneCallback(sid, null);
            } else {
                doneCallback("", "Tag '" + tag + "' not found.");
            }
        }, function () {
            failCallback("search: request error occured!");
        });
    }

    function read(sid, doneCallback, failCallback) {
        ajaxGet("read", sid, function (response) {
            if (response.Content) {


                var message = cryptor.decrypt(response.Content, response.Salt, response.IV);
                doneCallback(message, null);
            } else {
                doneCallback("", "SID '" + sid + "' not found.");
            }
        }, function () {
            failCallback("read: request error occured!");
        });
    }

    function create(id, tag, message, doneCallback, failCallback) {
        var o = cryptor.encryptForCreate(id, tag, message);
        ajaxPost("create", o, doneCallback, failCallback);
    }

    function deleteMessage(id, doneCallback, failCallback) {
        ajaxDelete("delete", id, doneCallback, failCallback);
    }

    this.searchTag = function (tag, doneCallback, failCallback) {
        search(tag, function (sid, searchError) {
            if (sid) {
                doneCallback("Tag '" + tag + "' found.", null)
            } else {
                doneCallback("", "Tag '" + tag + "' was not found.");
            }
        }, failCallback);
    };

    this.readMessage = function (tag, doneCallback, failCallback) {
        search(tag, function (sid, searchError) {
            if (sid) {
                read(sid, function (message, readError) {
                    doneCallback(message, readError);
                });
            } else {
                doneCallback("", searchError);
            }
        }, failCallback);
    };

    this.createMessage = function (tag, message, doneCallback, failCallback) {
        search(tag, function (sid, searchError) {
            if (sid) {
                doneCallback("", "Tag '" + tag + "' already exists.")
            } else {
                id(function (newId) {
                    create(newId, tag, message, function () {
                        doneCallback("Tag '" + tag + "' successfully created.", null);
                    }, function () {
                        failCallback("create: request error occured!");
                    });
                }, function () {
                    doneCallback("", "Id generation failed.");
                });
            }
        }, failCallback);
    };

    this.deleteMessage = function (tag, doneCallback, failCallback) {
        search(tag, function (sid, searchError) {
            if (sid) {
                deleteMessage(sid, function () {
                    doneCallback("Tag '" + tag + "' successfully deleted.", null);
                }, function () {
                    failCallback("delete: request error occured!");
                });
            } else {
                doneCallback("", searchError);
            }
        }, failCallback);
    };
}
