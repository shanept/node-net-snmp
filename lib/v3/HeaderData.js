var Constants = require("../constants");
var ber = require ("asn1").Ber;

var HeaderData = function() {
	var id, max, flags, securityModel;

	Object.defineProperties(this, {
		'msgID': {
			set: function(value) {
				if (value < 0 || value > Constants.maxInt) {
					throw new RangeError(value + " is not a valid message identifier.");
				}

				msgID = value;
			},
			get: function() { return msgID; }
		},
		'msgMaxSize': {
			set: function(value) {
				if (value < 484 || value > Constants.maxInt) {
					throw new RangeError(value + " is not a valid maximum message size.");
				}

				max = value;
			},
			get: function() { return max; }
		},
		'msgFlags': {
			set: function(value) {
				if (value & Constants.BitwiseFlags.Priv &&
					!(value & Constants.BitwiseFlags.Auth)) {

					throw new UnsupportedSecurityLevel("Can not set privacy without authentication.")
				}

				if (value > (Constants.BitwiseFlags.Auth &
							 Constants.BitwiseFlags.Priv &
							 Constants.BitwiseFlags.Reportable) ||
					value < 0) {

					throw new RangeError(value + " is not a valid message flag.");
				}

				flags = value;
			},
			get: function() { return flags; }
		},
		'msgSecurityModel': {
			set: function(value) {
				// We currently only support one model...
				if (msgSecurityModel !== Constants.SecurityModel.USM) {
					throw new Error("Unknown security model - not supported!");
				}

				if (value < 1 || value > Constants.maxInt) {
					throw new RangeError(value + " is not a valid security model.");
				}

				securityModel = value;
			},
			get: function() { return securityModel; }
		},

		// The following are convenience-wrappers around the msgFlags value
		'auth': {
			set: function(value) {
				var flags = this.msgFlags;

				if (value) {
					flags |= Constants.BitwiseFlags.Auth;
				} else if (flags & Constants.BitwiseFlags.Auth) {
					flags ^= Constants.BitwiseFlags.Auth;
				}

				this.msgFlags = flags;
			},
			get: function(value) {
				return (this.msgFlags | Constants.BitwiseFlags.Auth);
			}
		},
		'priv': {
			set: function(value) {
				var flags = this.msgFlags;

				if (value) {
					flags |= Constants.BitwiseFlags.Priv;
				} else if (flags & Constants.BitwiseFlags.Priv) {
					flags ^= Constants.BitwiseFlags.Priv;
				}

				this.msgFlags = flags;
			},
			get: function(value) {
				return (this.msgFlags | Constants.BitwiseFlags.Priv);
			}
		},
		'reportable': {
			set: function(value) {
				var flags = this.msgFlags;

				if (value) {
					flags |= Constants.BitwiseFlags.Reportable;
				} else if (flags & Constants.BitwiseFlags.Reportable) {
					flags ^= Constants.BitwiseFlags.Reportable;
				}

				this.msgFlags = flags;
			},
			get: function(value) {
				return (this.msgFlags | Constants.BitwiseFlags.Reportable);
			}
		}
	});
};

HeaderData.prototype.toBuffer = function(buffer) {
	buffer.startSequence();

	buffer.writeInt (this.msgID);
	buffer.writeInt (this.msgMaxSize);
	buffer.writeByte (this.msgFlags);
	buffer.writeInt (this.msgSecurityModel);

	buffer.endSequence();
};

module.exports = HeaderData;
