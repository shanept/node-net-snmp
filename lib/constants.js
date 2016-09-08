function _expandConstantObject (object) {
	var keys = [];
	for (var key in object)
		keys.push (key);
	for (var i = 0; i < keys.length; i++)
		object[object[keys[i]]] = parseInt (keys[i]);
}

var Version1 = 0;
var Version2c = 1;
var Version2u = 2;  // Un-implemented and un-used.
var Version3 = 3;

var ErrorStatus = {
	0: "NoError",
	1: "TooBig",
	2: "NoSuchName",
	3: "BadValue",
	4: "ReadOnly",
	5: "GeneralError",
	6: "NoAccess",
	7: "WrongType",
	8: "WrongLength",
	9: "WrongEncoding",
	10: "WrongValue",
	11: "NoCreation",
	12: "InconsistentValue",
	13: "ResourceUnavailable",
	14: "CommitFailed",
	15: "UndoFailed",
	16: "AuthorizationError",
	17: "NotWritable",
	18: "InconsistentName"
};

_expandConstantObject (ErrorStatus);

var ObjectType = {
	1: "Boolean",
	2: "Integer",
	4: "OctetString",
	5: "Null",
	6: "OID",
	64: "IpAddress",
	65: "Counter",
	66: "Gauge",
	67: "TimeTicks",
	68: "Opaque",
	70: "Counter64",
	128: "NoSuchObject",
	129: "NoSuchInstance",
	130: "EndOfMibView"
};

_expandConstantObject (ObjectType);

ObjectType.Integer32 = ObjectType.Integer;
ObjectType.Counter32 = ObjectType.Counter;
ObjectType.Gauge32 = ObjectType.Gauge;
ObjectType.Unsigned32 = ObjectType.Gauge32;

var PduType = {
	160: "GetRequest",
	161: "GetNextRequest",
	162: "GetResponse",
	163: "SetRequest",
	164: "Trap",
	165: "GetBulkRequest",
	166: "InformRequest",
	167: "TrapV2",
	168: "Report"
};

_expandConstantObject (PduType);

var TrapType = {
	0: "ColdStart",
	1: "WarmStart",
	2: "LinkDown",
	3: "LinkUp",
	4: "AuthenticationFailure",
	5: "EgpNeighborLoss",
	6: "EnterpriseSpecific"
};

_expandConstantObject (TrapType);

var SecurityModel = {
	0: "any",		// reserved
	1: "SNMPv1",	// reserved
	2: "SNMPv2c",	// reserved
	3: "USM"		// User-based Security Model (USM)
};

_expandConstantObject (SecurityModel);

var BitwiseFlags = {
	1: 'Auth',
	2: 'Priv',
	4: 'Reportable'
};

_expandConstantObject (BitwiseFlags);

var Flags = {
	0: 'NoAuthNoPriv',
	1: 'AuthNoPriv',
	3: 'AuthPriv',
};

_expandConstantObject (Flags);

var AuthTypes = {
	0: 'MD5',			// HMAC-MD5-96
	1: 'SHA'			// HMAC-SHA-96
};

_expandConstantObject (AuthTypes);

var PrivTypes = {
	0: 'DES',			// CBC-DES
};

_expandConstantObject (PrivTypes);

module.exports = {
	Version1: Version1,
	Version2c: Version2c,
	Version3: Version3,
	ErrorStatus: ErrorStatus,
	ObjectType: ObjectType,
	PduType: PduType,
	TrapType: TrapType,
	SecurityModel: SecurityModel,
	BitwiseFlags: BitwiseFlags,
	Flags: Flags
};
