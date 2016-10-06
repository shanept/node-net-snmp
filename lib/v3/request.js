var Constants = require("../constants");
var USM = require ("./auth/USM");
var ScopedPDU = require("./ScopedPdu");
var ber = require ("asn1").Ber;

var RequestMessage = function(session, options) {
	if (options.version < Constants.Version3 || options.version > Constants.maxInt) {
		throw new RangeError(version + " is not an acceptable version.");
	}

	this.options = options;
};

/**
 * Simple polyfill to support old method until SNMPv2 and dispatcher are
 * rewritten to call prepareOutgoingMessage instead
 */
RequestMessage.prototype.toBuffer = function() {
	return this.prepareOutgoingMessage(this.options.PDU);
};

RequestMessage.prototype.prepareOutgoingMessage = function(pdu) {
	if (this.buffer)
		return this.buffer;

	// Instantiate header
	var header = new HeaderData;
	//  Use the lower WORD of the SNMP engine boots as the
	//  higher WORD of the ID, and the lower WORD of the request
	//  count as the lower WORD of the ID.
	header.msgID = LOWORD(session.boots) << 16 | LOWORD(session.reqCount);
	header.msgMaxSize = session.maxSize;				// Is there a better way?
	header.mgsFlags = this.options.securityLevel;
	header.msgSecurityModel = this.options.securityModel;

	// Instantiate security model
	var security = new this[this.options.securityModel](this, {
		messageProcessingModel: this.options.version,
		globalData: header,
		maxMessageSize: session.maxSize,				// Is there a better way?
		securityModel: this.options.securityModel,
		securityEngineId: session.engineID,				// Is there a better way?
		securityName: this.options.securityName,
		securityLevel: this.options.securityLevel
	});

	// RFC 3412 subsectoin 7.1.6
	var scopedPDU = new ScopedPDU;
	scopedPDU.contextEngineID = this.options.contextEngineID;
	scopedPDU.contextName = this.options.contextName;
	scopedPDU.data = pdu;

	var writer = new ber.Writer ();

	writer.startSequence ();

	writer.writeInt (this.version);

	header.toBuffer (writer);

	var message = security.generateRequestMessage (scopedPDU),
		statusInformation = message.statusInformation,
		securityParams = message.securityParameters,
		scopedPDU = message.scopedPDU;

	if (!statusInformation) {
		throw new Error("Couldn't generate a request message.");
	}

	securityParams.toBuffer (writer);
	msgData.toBuffer (scopedPDU);

	writer.endSequence();

	this.buffer = writer.buffer;

	return this.buffer;
};

module.export = RequestMessage;
