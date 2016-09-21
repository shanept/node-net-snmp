var Constants = require("./constants");
var ber = require ("asn1").Ber;

var HeaderData = function(msgID, msgMaxSize, msgFlags, msgSecurityModel) {
	if (msgID < 0 || msgID > 2147483647) {
		throw new RangeError(msgID + " is not a valid message identifier.");
	}

	if (msgMaxSize < 484 || msgMaxSize > 2147483647) {
		throw new RangeError(msgMaxSize + " is not a valid maximum message size.");
	}

	if (msgSecurityModel < 1 || msgSecurityModel > 2147483647) {
		throw new RangeError(msgSecurityModel + " is not a valid security model.");
	}

	// Do we require authentication?
	if (msgFlags & Constants.BitwiseFlags.Auth) {
		// We currently only support User-based Security Model
		if (msgSecurityModel !== Constants.SecurityModel.USM) {
			throw new Error("Unknown security model - not supported!");
		}
	} else if (msgFlags & Constants.BitwiseFlags.Priv) {
		throw new UnsupportedSecurityLevel("Can not set privacy without authentication.");
	} else {
		msgSecurityModel = 0;
	}

	this.id = msgID;
	this.max = msgMaxSize;
	this.flags = msgFlags & (Constants.BitwiseFlags.Auth |
							 Constants.BitwiseFlags.Priv |
							 Constants.BitwiseFlags.Reportable);
	this.securityModel = msgSecurityModel;
};

HeaderData.prototype.toBuffer = function(buffer) {
	buffer.startSequence();

	buffer.writeInt (this.id);
	buffer.writeInt (this.max);
	buffer.writeByte (this.flags);
	buffer.writeInt (this.securityModel);

	buffer.endSequence();
};

module.exports = HeaderData;
