var Constants = require('../constants');
var Ber = require('asn1').Ber;
var PDU = require('../pdu');

var RequestMessage = function (session) {
  if (session.version !== Constants.Version1 && session.version !== Constants.Version2c) {
    throw new RangeError(session.version + ' is not an acceptable version.');
  }

  this.session = session;
};

RequestMessage.prototype.prepareOutgoingMessage = function (message) {
  var _this = this;

  return new Promise(function (resolve, reject) {
    if (_this.buffer) {
      resolve({
        statusInformation: true,
        destTransportDomain: message.destTransportDomain,
        destTransportAddress: message.destTransportAddress,
        outgoingMessage: message.outgoingMessage,
      });
      return;
    }

    var writer = new Ber.Writer();

    writer.startSequence();

    writer.writeInt(_this.session.version);
    writer.writeString(_this.session.community);

    message.PDU.toBuffer(writer);

    writer.endSequence();

    message.outgoingMessage = writer.buffer;

    resolve({
      statusInformation: true,
      destTransportDomain: message.destTransportDomain,
      destTransportAddress: message.destTransportAddress,
      outgoingMessage: message.outgoingMessage,
    });
  });
};

RequestMessage.prototype.prepareDataElements = function (wholeMsg) {
  var _this = this;

  return new Promise(function (resolve, reject) {
    try {
      debugger;
      var buffer = new Ber.Reader(wholeMsg);

      buffer.readSequence();

      var version   = buffer.readInt();
      var community = buffer.readString();

      var type = buffer.peek();

      if (type == Constants.PduType.GetResponse) {
        var pdu = new PDU.GetResponsePdu(buffer);
      } else {
        throw new ResponseInvalidError("Unknown PDU type '" + type + "' in response");
      }

      // There is no point implementing a full security model for this
      if (community !== _this.session.community) {
        throw new Exceptions.ResponseInvalidError("Community '"
           + _this.session.community + "' in request does not match community '"
           + community + "' in response");
      }

      /***************************************
       * Response definitions
       *  - messageProcessingModel: SNMP Version (2)
       *  - securityModel: Unused (zero) as per RFC 3411
       *  - securityName: Unused - empty string
       *  - securityLevel: NoAuthNoPriv
       *  - contextEngineID: undefined
       *  - contextName: undefined
       *  - pduVersion: 1??
       *  - PDU: var pdu
       *  - pduType: var type
       *  - sendPduHandle: ??
       *  - maxSizeResponseScopedPDU: ???
       *  - statusInformation: true
       */
      resolve({
        messageProcessingModel: version,
        securityModel: 0,
        securityName: '',
        securityLevel: Constants.Flags.NoAuthNoPriv,
        contextEngineID: undefined,
        contextName: undefined,
        pduVersion: 1,
        PDU: pdu,
        pduType: type,
        sendPduHandle: undefined,
        maxSizeResponseScopedPDU: undefined,
        statusInformation: true,
      });
    } catch (reason) {
      reject(reason);
    }
  });
};

module.exports = RequestMessage;
