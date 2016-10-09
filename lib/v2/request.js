var Constants = require ("../constants");
var ber = require ("asn1").Ber;

var RequestMessage = function (session, options) {
	if (session.version !== Constants.Version1 && session.version !== Constants.Version2c) {
		throw new RangeError(session.version + " is not an acceptable version.");
	}

	this.session = session;
	this.options = options;
};

RequestMessage.prototype.toBuffer = function () {
	return this.prepareOutgoingMessage(this.options.PDU);
};

RequestMessage.prototype.prepareOutgoingMessage = function(pdu) {
	var me = this;

	return new Promise(function (resolve, reject) {
		if (me.buffer) {
			resolve({
				statusInformation: true,
				destTransportDomain: me.options.destTransportDomain,
				destTransportAddress: me.options.destTransportAddress,
				outgoingMessage: me.buffer
			});
			return;
		}

		var writer = new ber.Writer ();

		writer.startSequence ();

		writer.writeInt (me.session.version);
		writer.writeString (me.session.community);

		pdu.toBuffer (writer);

		writer.endSequence ();

		me.buffer = writer.buffer;

		resolve({
			statusInformation: true,
			destTransportDomain: me.options.destTransportDomain,
			destTransportAddress: me.options.destTransportAddress,
			outgoingMessage: me.buffer
		});
	});
};

module.exports = RequestMessage;
