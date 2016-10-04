var crypto = require('crypto');

var MD5 = function(options) {
    
};

// Appendix 2.1
MD5.prototype.hashPassphrase = function(password) {
    var md = crypto.createHash('md5'),
        count = 0,
        password_index = 0;

    // Use while loop until we've done 1 Megabyte
    while (count < 1048576) {
        let buffer = '';
        for (let i = 0; i < 64; i++) {
            /*************************************************/
            /* Take the next octet of the password, wrapping */
            /* to the beginning of the password as necessary.*/
            /*************************************************/
            buffer += password[password_index++ % password.length];
        }

        md.update(buffer);
        count += 64;
    }

    return md.digest();
};

// 2.6
MD5.prototype.localizeKey = function(key, snmpEngineID) {
    var md = crypto.createHash('md5');

    // Envelop snmpEngineID in the key
    md.update(key + snmpEngineID + key);

    return md.digest();
};

MD5.prototype.authenticateOutgoingMsg = function(authKey, securityParameters) {
    return {
        statusInformation: true,
        authParameters: parameters
    };
};

module.exports = MD5;
