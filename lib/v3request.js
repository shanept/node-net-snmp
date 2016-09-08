var Constants = require("./constants");
var ber = require ("asn1").Ber;

var RequestMessage = function(version, msgGlobalData, msgSecurityParams, msgData) {
	if (version < Constants.Version3 || version > 2147483647) {
		throw new RangeError(version + " is not an acceptable version.");
	}

	this.version = version;
	this.globalData = msgGlobalData;
	this.securityParams = msgSecurityParams;

	this.msgData = msgData;
};

RequestMessage.prototype.toBuffer = function() {
	return this.prepareOutgoingMessage(this.msgData);
};

RequestMessage.prototype.prepareOutgoingMessage = function(pdu) {
	if (this.buffer)
		return this.buffer;

	var writer = new ber.Writer ();

	writer.startSequence();

	writer.writeInt (this.version);

	this.globalData.toBuffer (writer);
	this.securityParams.generateRequestMessage (writer, pdu);

	writer.endSequence();

	this.buffer = writer.buffer;

	return this.buffer;
};

module.export = RequestMessage;
