var ber = require ("asn1").Ber;

var RequestMessage = function (version, community, pdu) {
	this.version = version;
	this.community = community;
	this.pdu = pdu;
};

RequestMessage.prototype.toBuffer = function () {
	var me = this;

	return new Promise(function (resolve, reject) {
		try {
			if (me.buffer) {
				resolve(me.buffer);
				return;
			}

			var writer = new ber.Writer ();

			writer.startSequence ();

			writer.writeInt (me.version);
			writer.writeString (me.community);

			me.pdu.toBuffer (writer);

			writer.endSequence ();

			me.buffer = writer.buffer;

			resolve(me.buffer);
		} catch (error) {
			reject(error);
		}
	});
};

module.exports = RequestMessage;
