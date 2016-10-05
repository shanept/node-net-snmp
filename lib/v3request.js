var Constants = require("./constants");
var ber = require ("asn1").Ber;

var RequestMessage = function(version, msgGlobalData, msgSecurityParams, msgData) {
	if (version < Constants.Version3 || version > Constants.maxInt) {
		throw new RangeError(version + " is not an acceptable version.");
	}

	this.version = version;
	this.globalData = msgGlobalData;
	this.securityParams = msgSecurityParams;

	this.msgData = msgData;
};

/**
 * Simple polyfill to support old method until SNMPv2 and dispatcher are
 * rewritten to call prepareOutgoingMessage instead
 */
RequestMessage.prototype.toBuffer = function() {
	return this.prepareOutgoingMessage(this.msgData);
};

RequestMessage.prototype.prepareOutgoingMessage = function(pdu) {
	if (this.buffer)
		return this.buffer;

	var writer = new ber.Writer ();

	writer.startSequence ();

	writer.writeInt (this.version);

	this.globalData.toBuffer (writer);
	var {
		statusInformation,
		securityParams,
		pdu
	} = this.securityParams.generateRequestMessage (pdu);

	if (!statusInformation) {
		throw new Error("Couldn't generate a request message.");
	}

	securityParams.toBuffer (writer);
	msgData.toBuffer (pdu);

	writer.endSequence();

	this.buffer = writer.buffer;

	return this.buffer;
};

module.export = RequestMessage;
