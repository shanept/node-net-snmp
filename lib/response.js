var Constants = require("./constants");
var PDU = require("./pdu");
var ber = require ("asn1").Ber;

var ResponseMessage = function (buffer) {
	var reader = new ber.Reader (buffer);

	reader.readSequence ();

	this.version = reader.readInt ();
	this.community = reader.readString ();

	var type = reader.peek ();

	if (type == Constants.PduType.GetResponse) {
		this.pdu = new PDU.GetResponsePdu (reader);
	} else {
		throw new Exceptions.ResponseInvalidError ("Unknown PDU type '" + type
				+ "' in response");
	}
};

module.exports = ResponseMessage;
