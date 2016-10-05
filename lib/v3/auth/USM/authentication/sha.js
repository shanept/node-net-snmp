var SHA = function(options) {
    
};

// Appendix 2.2
SHA.prototype.hashPassphrase = function(password) {
    var sh = crypto.createHash('sha1'),
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

        sh.update(buffer);
        count += 64;
    }

    return sh.digest();
};

// 2.6
SHA.prototype.localizeKey = function(key, snmpEngineID) {
    var sh = crypto.createHash('sha1');

    // Envelop snmpEngineID in the key
    sh.update(key + snmpEngineID + key);

    return sh.digest();
};

SHA.prototype.authenticateOutgoingMsg = function(authKey, securityParameters) {
    return {
        statusInformation: true,
        authParameters: parameters
    };
};

module.exports = SHA;
