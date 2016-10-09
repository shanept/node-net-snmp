var Constants = require("../../../constants.js");

var UsmSecurityParameters = function() {
    this.msgAuthoritativeEngineId = '';     // octet string
    var  msgAuthoritativeEngineBoots = 0;   // integer
    var  msgAuthoritativeEngineTime = 0;    // integer
    var  msgUserName = '';                  // octet string
    this.msgAuthenticationParameters = '';  // octet string
    this.msgPrivacyParameters = '';         // octet string

    Object.defineProperties(this, {
        'msgAuthoritativeEngineBoots': {
            set: function(value) {
                if (value < 0) {
                    throw new Error('UsmSecurityParameters.msgAuthoritativeEngineBoots' +
                     ' must not be less than 0.');
                }
                if (value > Constants.maxInt) {
                    throw new Error('UsmSecurityParameters.msgAuthoritativeEngineBoots' +
                     ' must not be greater than ' + Constants.maxInt + '.');
                }

                msgAuthoritativeEngineBoots = value;
            },
            get: function() { return msgAuthoritativeEngineBoots; }
        },
        'msgAuthoritativeEngineTime': {
            set: function(value) {
                if (value < 0) {
                    throw new Error('UsmSecurityParameters.msgAuthoritativeEngineTime' +
                     ' must not be less than 0.');
                }
                if (value > Constants.maxInt) {
                    throw new Error('UsmSecurityParameters.msgAuthoritativeEngineTime' +
                     ' must not be greater than ' + Constants.maxInt + '.');
                }

                msgAuthoritativeEngineTime = value;
            },
            get: function() { return msgAuthoritativeEngineTime; }
        },
        'msgUserName': {
            set: function(value) {
                if (value.length > 32) {
                    throw new Error('UsmSecurityParameters.msgUserName must' +
                     ' not be longer than 32 characters.');
                }

                msgUserName = value;
            },
            get: function() { return msgUserName; }
        }
    });
};

UsmSecurityParameters.prototype.toBuffer = function(buffer) {
    buffer.startSequence();

    buffer.writeString (this.msgAuthoritativeEngineId);
    buffer.writeInt (this.msgAuthoritativeEngineBoots);
    buffer.writeInt (this.msgAuthoritativeEngineTime);
    buffer.writeString (this.msgUserName);
    buffer.writeString (this.msgAuthenticationParameters);
    buffer.writeString (this.msgPrivacyParameters);

    buffer.endSequence();
};

module.exports = UsmSecurityParameters;
