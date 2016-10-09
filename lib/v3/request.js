var Constants = require("../constants");
var Functions = require("../functions");
var USM = require ("./auth/USM");
var ScopedPDU = require("./ScopedPdu");
var HeaderData = require ("./HeaderData");
var ber = require ("asn1").Ber;

var LOWORD = Functions.LOWORD;

var RequestMessage = function(session, options) {
	if (session.version < Constants.Version3 || session.version > Constants.maxInt) {
		throw new RangeError(options.version + " is not an acceptable version.");
	}

	this.session = session;
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
	var me = this;

	return new Promise(function(resolve, reject) {
		// If we have already generated the message, send it.
		if (me.buffer) {
			resolve({
				statusInformation: true,
				destTransportDomain: me.options.destTransportDomain,
				destTransportAddress: me.options.destTransportAddress,
				outgoingMessage: me.buffer
			});
			return;
		}

		// 7.1.6
		var scopedPDU = new ScopedPDU;
		scopedPDU.contextEngineID = me.options.contextEngineID;
		scopedPDU.contextName = me.options.contextName;
		scopedPDU.data = pdu;

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
		header.msgFlags = me.options.securityLevel;
		header.reportable = (Functions.isConfirmed(pdu) ? 1 : 0);
		header.msgSecurityModel = me.options.securityModel;

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
		var SecurityModelClassName = Constants.SecurityModel[me.options.securityModel];
		eval('var security = new ' + SecurityModelClassName + '(me)');	// Eww...
		var securityParameters = {
			messageProcessingModel: me.options.messageProcessingModel,
			globalData: header,
			maxMessageSize: me.session.maxSize,				// Is there a better way?
			securityModel: me.options.securityModel,
			securityEngineId: me.session.engineID,			// Is there a better way?
			securityName: me.options.securityName,
			securityLevel: me.options.securityLevel,
			scopedPDU: scopedPDU
		};

		var messagePromise = null;

		if (Functions.inResponseClass(pdu) || Functions.inInternalClass(pdu)) {
			// generateResponseMsg
			throw new Error('Not yet implemented');
		} else if (Functions.isConfirmed(pdu) || Functions.inNotificationClass(pdu)) {
			if (Functions.isUnconfirmed(pdu)) {
				// This should always point to the local Engine ID. However,
				// this will do for now!
				securityParameters.securityEngineId = session.engineID;
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
				destTransportDomain: me.options.destTransportDomain,
				destTransportAddress: me.options.destTransportAddress,
				outgoingMessage: message.wholeMsg
			});
		});
	});
};

module.exports = RequestMessage;
