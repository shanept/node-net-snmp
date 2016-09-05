var Constants = require("./constants");

/*****************************************************************************
 ** OID and varbind helper functions
 **/

function isVarbindError (varbind) {
	return !!(varbind.type == Constants.ObjectType.NoSuchObject
	|| varbind.type == Constants.ObjectType.NoSuchInstance
	|| varbind.type == Constants.ObjectType.EndOfMibView);
}

function varbindError (varbind) {
	return (Constants.ObjectType[varbind.type] || "NotAnError") + ": " + varbind.oid;
}

function oidFollowsOid (oidString, nextString) {
	var oid = {str: oidString, len: oidString.length, idx: 0};
	var next = {str: nextString, len: nextString.length, idx: 0};
	var dotCharCode = ".".charCodeAt (0);

	function getNumber (item) {
		var n = 0;
		if (item.idx >= item.len)
			return null;
		while (item.idx < item.len) {
			var charCode = item.str.charCodeAt (item.idx++);
			if (charCode == dotCharCode)
				return n;
			n = (n ? (n * 10) : n) + (charCode - 48);
		}
		return n;
	}

	while (1) {
		var oidNumber = getNumber (oid);
		var nextNumber = getNumber (next);

		if (oidNumber !== null) {
			if (nextNumber !== null) {
				if (nextNumber > oidNumber) {
					return true;
				} else if (nextNumber < oidNumber) {
					return false;
				}
			} else {
				return true;
			}
		} else {
			return true;
		}
	}
}

function oidInSubtree (oidString, nextString) {
	var oid = oidString.split (".");
	var next = nextString.split (".");

	if (oid.length > next.length)
		return false;

	for (var i = 0; i < oid.length; i++) {
		if (next[i] != oid[i])
			return false;
	}

	return true;
}

/**
 ** Some SNMP agents produce integers on the wire such as 00 ff ff ff ff.
 ** The ASN.1 BER parser we use throws an error when parsing this, which we
 ** believe is correct.  So, we decided not to bother the "asn1" developer(s)
 ** with this, instead opting to work around it here.
 **
 ** If an integer is 5 bytes in length we check if the first byte is 0, and if so
 ** simply drop it and parse it like it was a 4 byte integer, otherwise throw
 ** an error since the integer is too large.
 **/

function readInt (buffer) {
	return readUint (buffer, true);
}

function readUint (buffer, isSigned) {
	buffer.readByte ();
	var length = buffer.readByte ();
	var value = 0;
	var signedBitSet = false;

	if (length > 5) {
		 throw new RangeError ("Integer too long '" + length + "'");
	} else if (length == 5) {
		if (buffer.readByte () !== 0)
			throw new RangeError ("Integer too long '" + length + "'");
		length = 4;
	}

	for (var i = 0; i < length; i++) {
		value *= 256;
		value += buffer.readByte ();

		if (isSigned && i <= 0) {
			if ((value & 0x80) == 0x80)
				signedBitSet = true;
		}
	}

	if (signedBitSet)
		value -= (1 << (i * 8));

	return value;
}

function readUint64 (buffer) {
	var value = buffer.readString (Constants.ObjectType.Counter64, true);

	return value;
}

function readVarbinds (buffer, varbinds) {
	buffer.readSequence ();

	while (1) {
		buffer.readSequence ();
		var oid = buffer.readOID ();
		var type = buffer.peek ();

		if (type == null)
			break;

		var value;

		if (type == Constants.ObjectType.Boolean) {
			value = buffer.readBoolean ();
		} else if (type == Constants.ObjectType.Integer) {
			value = readInt (buffer);
		} else if (type == Constants.ObjectType.OctetString) {
			value = buffer.readString (null, true);
		} else if (type == Constants.ObjectType.Null) {
			buffer.readByte ();
			buffer.readByte ();
			value = null;
		} else if (type == Constants.ObjectType.OID) {
			value = buffer.readOID ();
		} else if (type == Constants.ObjectType.IpAddress) {
			var bytes = buffer.readString (Constants.ObjectType.IpAddress, true);
			if (bytes.length != 4)
				throw new Exceptions.ResponseInvalidError ("Length '" + bytes.length
						+ "' of IP address '" + bytes.toString ("hex")
						+ "' is not 4");
			value = bytes[0] + "." + bytes[1] + "." + bytes[2] + "." + bytes[3];
		} else if (type == Constants.ObjectType.Counter) {
			value = readUint (buffer);
		} else if (type == Constants.ObjectType.Gauge) {
			value = readUint (buffer);
		} else if (type == Constants.ObjectType.TimeTicks) {
			value = readUint (buffer);
		} else if (type == Constants.ObjectType.Opaque) {
			value = buffer.readString (Constants.ObjectType.Opaque, true);
		} else if (type == Constants.ObjectType.Counter64) {
			value = readUint64 (buffer);
		} else if (type == Constants.ObjectType.NoSuchObject) {
			buffer.readByte ();
			buffer.readByte ();
			value = null;
		} else if (type == Constants.ObjectType.NoSuchInstance) {
			buffer.readByte ();
			buffer.readByte ();
			value = null;
		} else if (type == Constants.ObjectType.EndOfMibView) {
			buffer.readByte ();
			buffer.readByte ();
			value = null;
		} else {
			throw new Exceptions.ResponseInvalidError ("Unknown type '" + type
					+ "' in response");
		}

		varbinds.push ({
			oid: oid,
			type: type,
			value: value
		});
	}
}

function writeUint (buffer, type, value) {
	var b = new Buffer (4);
	b.writeUInt32BE (value, 0);
	buffer.writeBuffer (b, type);
}

function writeUint64 (buffer, value) {
	buffer.writeBuffer (value, Constants.ObjectType.Counter64);
}

function writeVarbinds (buffer, varbinds) {
	buffer.startSequence ();
	for (var i = 0; i < varbinds.length; i++) {
		buffer.startSequence ();
		buffer.writeOID (varbinds[i].oid);

		if (varbinds[i].type && varbinds[i].hasOwnProperty("value")) {
			var type = varbinds[i].type;
			var value = varbinds[i].value;

			if (type == Constants.ObjectType.Boolean) {
				buffer.writeBoolean (value ? true : false);
			} else if (type == Constants.ObjectType.Integer) { // also Integer32
				buffer.writeInt (value);
			} else if (type == Constants.ObjectType.OctetString) {
				if (typeof value == "string")
					buffer.writeString (value);
				else
					buffer.writeBuffer (value, Constants.ObjectType.OctetString);
			} else if (type == Constants.ObjectType.Null) {
				buffer.writeNull ();
			} else if (type == Constants.ObjectType.OID) {
				buffer.writeOID (value);
			} else if (type == Constants.ObjectType.IpAddress) {
				var bytes = value.split (".");
				if (bytes.length != 4)
					throw new Exceptions.RequestInvalidError ("Invalid IP address '"
							+ value + "'");
				buffer.writeBuffer (new Buffer (bytes), 64);
			} else if (type == Constants.ObjectType.Counter) { // also Counter32
				writeUint (buffer, Constants.ObjectType.Counter, value);
			} else if (type == Constants.ObjectType.Gauge) { // also Gauge32 & Unsigned32
				writeUint (buffer, Constants.ObjectType.Gauge, value);
			} else if (type == Constants.ObjectType.TimeTicks) {
				writeUint (buffer, Constants.ObjectType.TimeTicks, value);
			} else if (type == Constants.ObjectType.Opaque) {
				buffer.writeBuffer (value, Constants.ObjectType.Opaque);
			} else if (type == Constants.ObjectType.Counter64) {
				writeUint64 (buffer, value);
			} else {
				throw new Exceptions.RequestInvalidError ("Unknown type '" + type
						+ "' in request");
			}
		} else {
			buffer.writeNull ();
		}

		buffer.endSequence ();
	}
	buffer.endSequence ();
}

function HIWORD(dword) {
	return (dword >> 16) & 0xFFFF;
}

function LOWORD(dword) {
	return dword & 0xFFFF;
}

module.exports = {
    isVarbindError: isVarbindError,
    varbindError: varbindError,
    oidFollowsOid: oidFollowsOid,
    oidInSubtree: oidInSubtree,
    readInt: readInt,
    readUint: readUint,
    readUint64: readUint64,
    readVarbinds: readVarbinds,
    writeUint: writeUint,
    writeUint64: writeUint64,
    writeVarbinds: writeVarbinds,
    HIWORD: HIWORD,
    LOWORD: LOWORD
};
