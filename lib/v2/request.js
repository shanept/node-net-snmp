var ber = require ("asn1").Ber;

var RequestMessage = function (version, community, pdu) {
	this.version = version;
	this.community = community;
	this.pdu = pdu;
};

RequestMessage.prototype.toBuffer = function () {
	if (this.buffer)
		return this.buffer;

	var writer = new ber.Writer ();

	writer.startSequence ();

	writer.writeInt (this.version);
	writer.writeString (this.community);

	this.pdu.toBuffer (writer);

	writer.endSequence ();

	this.buffer = writer.buffer;

	return this.buffer;
};

module.exports = RequestMessage;
