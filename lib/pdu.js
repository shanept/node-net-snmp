var Constants = require("./constants");
var util = require ("util");

var SimplePdu = function (id, varbinds, options) {
	this.id = id;
	this.varbinds = varbinds;
	this.options = options || {};
};

SimplePdu.prototype.toBuffer = function (buffer) {
	buffer.startSequence (this.type);

	buffer.writeInt (this.id);
	buffer.writeInt ((this.type == Constants.PduType.GetBulkRequest)
			? (this.options.nonRepeaters || 0)
			: 0);
	buffer.writeInt ((this.type == Constants.PduType.GetBulkRequest)
			? (this.options.maxRepetitions || 0)
			: 0);

	writeVarbinds (buffer, this.varbinds);

	buffer.endSequence ();
};

var GetBulkRequestPdu = function () {
	this.type = Constants.PduType.GetBulkRequest;
	GetBulkRequestPdu.super_.apply (this, arguments);
};

util.inherits (GetBulkRequestPdu, SimplePdu);

var GetNextRequestPdu = function () {
	this.type = Constants.PduType.GetNextRequest;
	GetNextRequestPdu.super_.apply (this, arguments);
};

util.inherits (GetNextRequestPdu, SimplePdu);

var GetResponsePdu = function (buffer) {
	this.type = Constants.PduType.GetResponse;

	buffer.readSequence (this.type);

	this.id = buffer.readInt ();

	this.errorStatus = buffer.readInt ();
	this.errorIndex = buffer.readInt ();

	this.varbinds = [];

	readVarbinds (buffer, this.varbinds);
};

var GetRequestPdu = function () {
	this.type = Constants.PduType.GetRequest;
	GetRequestPdu.super_.apply (this, arguments);
};

util.inherits (GetRequestPdu, SimplePdu);

var InformRequestPdu = function () {
	this.type = Constants.PduType.InformRequest;
	InformRequestPdu.super_.apply (this, arguments);
};

util.inherits (InformRequestPdu, SimplePdu);

var SetRequestPdu = function () {
	this.type = Constants.PduType.SetRequest;
	SetRequestPdu.super_.apply (this, arguments);
};

util.inherits (SetRequestPdu, SimplePdu);

var TrapPdu = function (typeOrOid, varbinds, options) {
	this.type = Constants.PduType.Trap;

	this.agentAddr = options.agentAddr || "127.0.0.1";
	this.upTime = options.upTime;

	if (typeof typeOrOid == "string") {
		this.generic = Constants.TrapType.EnterpriseSpecific;
		this.specific = parseInt (typeOrOid.match (/\.(\d+)$/)[1]);
		this.enterprise = typeOrOid.replace (/\.(\d+)$/, "");
	} else {
		this.generic = typeOrOid;
		this.specific = 0;
		this.enterprise = "1.3.6.1.4.1";
	}

	this.varbinds = varbinds;
};

TrapPdu.prototype.toBuffer = function (buffer) {
	buffer.startSequence (this.type);

	buffer.writeOID (this.enterprise);
	buffer.writeBuffer (new Buffer (this.agentAddr.split (".")),
			Constants.ObjectType.IpAddress);
	buffer.writeInt (this.generic);
	buffer.writeInt (this.specific);
	writeUint (buffer, Constants.ObjectType.TimeTicks,
			this.upTime || Math.floor (process.uptime () * 100));

	writeVarbinds (buffer, this.varbinds);

	buffer.endSequence ();
};

var TrapV2Pdu = function () {
	this.type = Constants.PduType.TrapV2;
	TrapV2Pdu.super_.apply (this, arguments);
};

util.inherits (TrapV2Pdu, SimplePdu);

module.exports = {
	GetBulkRequestPdu: GetBulkRequestPdu,
	GetNextRequestPdu: GetNextRequestPdu,
	GetResponsePdu: GetResponsePdu,
	GetRequestPdu: GetRequestPdu,
	InformRequestPdu: InformRequestPdu,
	SetRequestPdu: SetRequestPdu,
	TrapPdu: TrapPdu,
	TrapV2Pdu: Trapv2Pdu
};
