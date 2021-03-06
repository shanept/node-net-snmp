var SHA = function (options) {
  // Nothing to do here
};

// Appendix 2.2
SHA.prototype.hashPassphrase = function (password) {
  var sh = crypto.createHash('sha1');
  var count = 0;
  var passwordIndex = 0;
  var buffer = '';

  // Use while loop until we've done 1 Megabyte
  while (count < 1048576) {
    buffer = '';
    for (var i = 0; i < 64; i++) {
      /*************************************************/
      /* Take the next octet of the password, wrapping */
      /* to the beginning of the password as necessary.*/
      /*************************************************/
      buffer += password[passwordIndex++ % password.length];
    }

    sh.update(buffer);
    count += 64;
  }

  return sh.digest();
};

// 2.6
SHA.prototype.localizeKey = function (key, snmpEngineID) {
  var sh = crypto.createHash('sha1');

  // Envelop snmpEngineID in the key
  sh.update(key + snmpEngineID + key);

  return sh.digest();
};

SHA.prototype.authenticateOutgoingMsg = function (authKey, securityParameters) {
  return {
    statusInformation: true,
    authParameters: parameters,
  };
};

module.exports = SHA;
