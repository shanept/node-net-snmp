var Constants = require("../constants");
var Functions = require("../functions");
var USM = require ("./auth/USM");
var UsmSecurityParameters = require("./auth/USM/UsmSecurityParameters");
var ScopedPDU = require("./ScopedPdu");
var HeaderData = require ("./HeaderData");
var Ber = require ("asn1").Ber;

var LOWORD = Functions.LOWORD;

var RequestMessage = function(session) {
	if (session.version < Constants.Version3 || session.version > Constants.maxInt) {
		throw new RangeError(session.version + " is not an acceptable version.");
	}

	this.session = session;
};

RequestMessage.prototype.prepareDataElements = function(wholeMsg) {
	return new Promise(function(resolve, reject) {
	try {
		var buffer = new Ber.Reader(wholeMsg);

		// RFP3412  7.2.3
		buffer.readSequence ();
		var version = buffer.readInt();

		var header = new HeaderData;
		header.fromBuffer(buffer);

		var params = new UsmSecurityParameters;
		params.fromBuffer(buffer);

		// Read the rest of the buffer manually
		var scopedPDUData = buffer._buf.slice(buffer._offset);
		var data = new Ber.Reader (scopedPDUData);

		resolve({
			messageProcessingModel: Constants.Version3,
			securityModel: null,
			securityName: null,
			securityLevel: null,
			contextEngineID: null,
			pduVersion: null,
			PDU: null,
			pduType: null,
			sendPduHandle: null,				// Handle for matched request
			maxSizeResponseScopedPDU: null,		// Maximum size sender can accept
			statusInformation: null,
			stateReference: null				// Used for a possible response
		});
	} catch (error) {
		reject(error);
	}
	});
};

RequestMessage.prototype.prepareOutgoingMessage = function(options) {
	var me = this;

	return new Promise(function(resolve, reject) {
		// If we have already generated the message, send it.
		if (me.buffer) {
			resolve({
				statusInformation: true,
				destTransportDomain: options.destTransportDomain,
				destTransportAddress: options.destTransportAddress,
				outgoingMessage: me.buffer
			});
			return;
		}

		// 7.1.6
		var scopedPDU = new ScopedPDU;
		scopedPDU.contextEngineID = options.contextEngineID;
		scopedPDU.contextName = options.contextName;
		scopedPDU.data = options.PDU;

		/**
		 * 7.1.7 - Instantiate header data
		 *
		 * msgID:
		 *   The higher WORD of the msgID shall take the value of the lower
		 *   WORD of snmpEngineBoots, and the lower WORD shall be set to
		 *   the lower WORD of the engine request count.
		 *
		 * msgFlags:
		 *   If the PDU is a confirmed type, it will expect a response, and we
		 *   should set the reportable bit of msgFlags to 1. If the PDU is
		 *   unconfirmed, we do not expect a response and therefore we
		 *   must set this bit to 0.
		 **/

		var header = new HeaderData;
		header.msgID = LOWORD(me.session.boots) << 16 | LOWORD(me.session.reqCount);
		header.msgMaxSize = me.session.maxSize;				// Is there a better way?
		header.msgFlags = options.securityLevel;
		header.reportable = (Functions.isConfirmed(options.PDU) ? 1 : 0);
		header.msgSecurityModel = options.securityModel;

		/**
		 * 7.1.8 - Generate response
		 *
		 * If the message to be generated is a response message, the PDU will
		 * belong to either the response or internal class. The resulting
		 * message must be generated via 'generateResponseMsg' on the
		 * security model.
		 *
		 *
		 * 7.1.9 - Generate request
		 *
		 * If the message is not a response, however it is in either the Confirmed
		 * class or the Notification class, the message must be generated via
		 * 'generateRequestMsg' method on the same security model.
		 */
		var SecurityModelClassName = Constants.SecurityModel[options.securityModel];
		eval('var security = new ' + SecurityModelClassName + '(me)');	// Eww...
		var securityParameters = {
			messageProcessingModel: options.messageProcessingModel,
			globalData: header,
			maxMessageSize: me.session.maxSize,				// Is there a better way?
			securityModel: options.securityModel,
			securityEngineId: me.session.engineID,			// Is there a better way?
			securityName: options.securityName,
			securityLevel: options.securityLevel,
			scopedPDU: scopedPDU
		};

		var messagePromise = null;

		if (Functions.inResponseClass(options.PDU) || Functions.inInternalClass(options.PDU)) {
			// generateResponseMsg
			throw new Error('Not yet implemented');
		} else if (Functions.isConfirmed(options.PDU) || Functions.inNotificationClass(options.PDU)) {
			if (Functions.isUnconfirmed(options.PDU)) {
				// This should always point to the local Engine ID. However,
				// this will do for now!
				securityParameters.securityEngineId = me.session.engineID;
			} else {
				// Currently, we pass in the SNMP Engine ID of our target.
				// We shall use SNMP Engine ID discovery to figure out
				// the engine ID in the future.
			}

			messagePromise = security.generateRequestMsg(securityParameters);
		}

		messagePromise.then(function(message) {
			// We are simply modifying the parameters passed
			// through in reply to the message dispatcher
			resolve({
				statusInformation: true,
				destTransportDomain: options.destTransportDomain,
				destTransportAddress: options.destTransportAddress,
				outgoingMessage: message.wholeMsg
			});
		});
	});
};

module.exports = RequestMessage;
