var Constants = require("../../../constants.js");
var Ber = require("asn1").Ber;

var UsmSecurityParameters = function() {
    this.msgAuthoritativeEngineId = '';     // octet string
    var  msgAuthoritativeEngineBoots = 0;   // integer
    var  msgAuthoritativeEngineTime = 0;    // integer
    var  msgUserName = '';                  // octet string
    this.msgAuthenticationParameters = '';  // octet string
    this.msgPrivacyParameters = '';         // octet string

    Object.defineProperties(this, {
        'msgAuthoritativeEngineBoots': {
            enumerable: true,
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
            enumerable: true,
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
            enumerable: true,
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
    var writer = new Ber.Writer ();

    writer.startSequence ();

    writer.writeString (this.msgAuthoritativeEngineId);
    writer.writeInt (this.msgAuthoritativeEngineBoots);
    writer.writeInt (this.msgAuthoritativeEngineTime);
    writer.writeString (this.msgUserName);
    writer.writeString (this.msgAuthenticationParameters);
    writer.writeString (this.msgPrivacyParameters);

    writer.endSequence ();

    buffer.writeBuffer (writer.buffer, Ber.OctetString);
};

UsmSecurityParameters.prototype.fromBuffer = function(buffer) {
    var parameters = buffer.readString (Ber.OctetString, true);
    var reader = new Ber.Reader (parameters);

    reader.readSequence ();

    var engineID = reader.readString (Ber.OctetString, true);
    this.msgAuthoritativeEngineId = engineID.toString("hex");
    this.msgAuthoritativeEngineBoots = reader.readInt ();
    this.msgAuthoritativeEngineTime = reader.readInt ();
    this.msgUserName = reader.readString ();
    this.msgAuthenticationParameters = reader.readString ();
    this.msgPrivacyParameters = reader.readString ();
};

module.exports = UsmSecurityParameters;
