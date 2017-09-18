var Constants = require('./constants');
var Exceptions = require('./exceptions');
var Functions = require('./functions');
var PDU = require('./pdu');
var V2MPM = require('./v2/request');
var V3MPM = require('./v3/request');
var ResponseMessage = require('./response');
var USM = require('./v3/auth/USM');
var TimeWindow = require('./v3/TimeWindow');

var dgram = require('dgram');
var events = require('events');
var util = require('util');
var Ber = require('asn1').Ber;

/*****************************************************************************
 ** Import helper functions into local scope
 **/
var isVarbindError = Functions.isVarbindError;
var varbindError   = Functions.varbindError;
var oidFollowsOid  = Functions.oidFollowsOid;
var oidInSubtree   = Functions.oidInSubtree;
var readInt        = Functions.readInt;
var readUint       = Functions.readUint;
var readUint64     = Functions.readUint64;
var readVarBinds   = Functions.readVarbinds;
var writeUint      = Functions.writeUint;
var writeUint64    = Functions.writeUint64;
var writeVarbinds  = Functions.writeVarbinds;
var HIWORD         = Functions.HIWORD;
var LOWORD         = Functions.LOWORD;
var isConfirmed    = Functions.isConfirmed;

/*****************************************************************************
 ** Options processors
 **/
function SnmpProcessV2Options(options) {
  var processed = {};

  processed.transport = (options && options.transport)
      ? options.transport
      : 'udp4';
  processed.port = (options && options.port)
      ? options.port
      : 161;
  processed.trapPort = (options && options.trapPort)
      ? options.trapPort
      : 162;

  processed.retries = (options && (options.retries || options.retries == 0))
      ? options.retries
      : 1;
  processed.timeout = (options && options.timeout)
      ? options.timeout
      : 5000;

  processed.sourceAddress = (options && options.sourceAddress)
      ? options.sourceAddress
      : undefined;
  processed.sourcePort = (options && options.sourcePort)
      ? parseInt(options.sourcePort)
      : undefined;

  return processed;
}

function SnmpProcessV3Options(options) {
  var processed = {};

  processed = SnmpProcessV2Options(options);

  if (!options || !options.engineID) {
    throw new Error('Expected value for Engine ID. None provided.');
  }

  processed.engineID = options.engineID;
  processed.boots = (options.boots !== undefined
            ? options.boots
            : Constants.maxInt);
  processed.time = options.time || 0;

  processed.maxSize = (options && options.maxSize)
      ? options.maxSize
      : 65535;

  processed.flags = (options && options.flags)
      ? options.flags
      : Constants.Flags.NoAuthNoPriv;

  processed.contextEngineID = options.contextEngineID || options.engineID;
  processed.contextName = options.contextName || '';

  // Process message authentication options
  if (!(processed.flags & Constants.BitwiseFlags.Auth) &&
     (processed.flags & Constants.BitwiseFlags.Priv)) {

    throw new Error('Message privacy can not be set without authentication.');
  }

  if (processed.flags & Constants.BitwiseFlags.Auth) {
    if (!options.auth) {
      throw new Error('Message auth flag set but no auth specified.');
    }

    processed.auth = options.auth;
  }

  if ((processed.flags & Constants.BitwiseFlags.Auth) &&
    (processed.flags & Constants.BitwiseFlags.Priv)) {

    processed.priv = (options && options.priv)
      ? options.priv
      : null;
  }

  processed.securityModel = (options && options.securityModel)
      ? options.securityModel
      : 'USM';

  processed.securityName = (options && options.securityName)
      ? options.securityName
      : '';

  if (Object.keys(Constants.SecurityModel).indexOf(processed.securityModel.toString()) === -1) {
    throw new RangeError(processed.securityModel + ' is not a valid or supported security model.');
  }

  processed.UsmOptions = (options && options.UsmOptions)
      ? options.UsmOptions
      : {};

  return processed;
}

/*****************************************************************************
 ** Session class definition
 **/
var Session = function (target, options) {
  this.target = target || '127.0.0.1';

  this.version = (options && options.version)
      ? options.version
      : Constants.Version1;

  if (this.version < 0 || this.version > 3) {
    throw new Error("Invalid SNMP version '" + this.version + "'");
  }

  if (this.version < Constants.Version3) {
    this.community = options.community || 'public';
    options = SnmpProcessV2Options(options);
    Object.assign(this, options);
  } else {
    options = SnmpProcessV3Options(options);
    Object.assign(this, options);

    this.timeWindow = new TimeWindow(options.engineID);
    this.timeWindow.update(options.boots, options.time);
  }

  this.reqs = {};
  this.reqCount = 0;

  // Stores USM engine discovery data
  this.usm_timeline = [];

  this.dgram = dgram.createSocket(this.transport);
  this.dgram.unref();

  var _this = this;
  this.dgram.on('message', _this.onMsg.bind(_this));
  this.dgram.on('close', _this.onClose.bind(_this));
  this.dgram.on('error', _this.onError.bind(_this));

  if (this.sourceAddress || this.sourcePort)
    this.dgram.bind(this.sourcePort, this.sourceAddress);
};

util.inherits(Session, events.EventEmitter);

Session.prototype.close = function () {
  this.dgram.close();
  return this;
};

Session.prototype.cancelRequests = function (error) {
  var id;
  for (id in this.reqs) {
    var req = this.reqs[id];
    this.unregisterRequest(req.id);
    req.responseCb(error);
  }
};

function _generateId() {
  return Math.floor(Math.random() + Math.random() * 10000000);
}

Session.prototype.get = function (oids, responseCb) {
  function feedCb(req, message) {
    var pdu = message.PDU;
    var varbinds = [];

    if (req.pdu.varbinds.length != pdu.varbinds.length) {
      req.responseCb(new Exceptions.ResponseInvalidError('Requested OIDs do not '
          + 'match response OIDs'));
    } else {
      for (var i = 0; i < req.pdu.varbinds.length; i++) {
        if (req.pdu.varbinds[i].oid != pdu.varbinds[i].oid) {
          req.responseCb(new Exceptions.ResponseInvalidError("OID '"
              + req.pdu.varbinds[i].oid
              + "' in request at position '" + i + "' does not "
              + "match OID '" + pdu.varbinds[i].oid + "' in response "
              + "at position '" + i + "'"));
          return;
        } else {
          varbinds.push(pdu.varbinds[i]);
        }
      }

      req.responseCb(null, varbinds);
    }
  }

  var pduVarbinds = [];

  for (var i = 0; i < oids.length; i++) {
    var varbind = {
      oid: oids[i],
    };
    pduVarbinds.push(varbind);
  }

  this.simpleGet(PDU.GetRequestPdu, feedCb, pduVarbinds, responseCb);

  return this;
};

Session.prototype.getBulk = function () {
  var oids;
  var nonRepeaters;
  var maxRepetitions;
  var responseCb;

  if (arguments.length >= 4) {
    oids = arguments[0];
    nonRepeaters = arguments[1];
    maxRepetitions = arguments[2];
    responseCb = arguments[3];
  } else if (arguments.length >= 3) {
    oids = arguments[0];
    nonRepeaters = arguments[1];
    maxRepetitions = 10;
    responseCb = arguments[2];
  } else {
    oids = arguments[0];
    nonRepeaters = 0;
    maxRepetitions = 10;
    responseCb = arguments[1];
  }

  function feedCb(req, message) {
    var pdu = message.PDU;
    var varbinds = [];
    var i = 0;

    // first walk through and grab non-repeaters
    if (pdu.varbinds.length < nonRepeaters) {
      req.responseCb(new Exceptions.ResponseInvalidError('Varbind count in '
          + "response '" + pdu.varbinds.length + "' is less than "
          + "non-repeaters '" + nonRepeaters + "' in request"));
    } else {
      for (; i < nonRepeaters; i++) {
        if (isVarbindError(pdu.varbinds[i])) {
          varbinds.push(pdu.varbinds[i]);
        } else if (!oidFollowsOid(req.pdu.varbinds[i].oid, pdu.varbinds[i].oid)) {
          req.responseCb(new Exceptions.ResponseInvalidError("OID '"
              + req.pdu.varbinds[i].oid + "' in request at "
              + "position '" + i + "' does not precede "
              + "OID '" + pdu.varbinds[i].oid + "' in response "
              + "at position '" + i + "'"));

          return;
        } else {
          varbinds.push(pdu.varbinds[i]);
        }
      }
    }

    var repeaters = req.pdu.varbinds.length - nonRepeaters;

    // secondly walk through and grab repeaters
    if (pdu.varbinds.length % (repeaters)) {
      req.responseCb(new Exceptions.ResponseInvalidError('Varbind count in '
          + "response '" + pdu.varbinds.length + "' is not a "
          + "multiple of repeaters '" + repeaters  + "' plus non-repeaters '"
          + nonRepeaters + "' in request"));
    } else {
      while (i < pdu.varbinds.length) {
        for (var j = 0; j < repeaters; j++, i++) {
          var reqIndex = nonRepeaters + j;
          var respIndex = i;
          var reqOID = req.pdu.varbinds[reqIndex].oid;
          var respOID = pdu.varbinds[respIndex].oid;

          if (isVarbindError(pdu.varbinds[respIndex])) {
            if (!varbinds[reqIndex]) {
              varbinds[reqIndex] = [];
            }

            varbinds[reqIndex].push(pdu.varbinds[respIndex]);
          } else if (!oidFollowsOid(reqOID, respOID)) {
            req.responseCb(new Exceptions.ResponseInvalidError("OID '"
                + reqOID
                + "' in request at position '" + (reqIndex)
                + "' does not precede OID '" + respOID
                + "' in response at position '" + (respIndex) + "'"));

            return;
          } else {
            if (!varbinds[reqIndex]) {
              varbinds[reqIndex] = [];
            }

            varbinds[reqIndex].push(pdu.varbinds[respIndex]);
          }
        }
      }
    }

    req.responseCb(null, varbinds);
  }

  var pduVarbinds = [];

  for (var i = 0; i < oids.length; i++) {
    var varbind = {
      oid: oids[i],
    };
    pduVarbinds.push(varbind);
  }

  var options = {
    nonRepeaters: nonRepeaters,
    maxRepetitions: maxRepetitions,
  };

  this.simpleGet(PDU.GetBulkRequestPdu, feedCb, pduVarbinds, responseCb, options);

  return this;
};

Session.prototype.getNext = function (oids, responseCb) {
  function feedCb(req, message) {
    var pdu = message.PDU;
    var varbinds = [];

    if (req.pdu.varbinds.length != pdu.varbinds.length) {
      req.responseCb(new Exceptions.ResponseInvalidError('Requested OIDs do not '
          + 'match response OIDs'));
    } else {
      for (var i = 0; i < req.pdu.varbinds.length; i++) {
        if (isVarbindError(pdu.varbinds[i])) {
          varbinds.push(pdu.varbinds[i]);
        } else if (!oidFollowsOid(req.pdu.varbinds[i].oid, pdu.varbinds[i].oid)) {
          req.responseCb(new Exceptions.ResponseInvalidError("OID '"
              + req.pdu.varbinds[i].oid + "' in request at position '"
              + i + "' does not precede  OID '" + pdu.varbinds[i].oid
              + "' in response  at position '" + i + "'"));

          return;
        } else {
          varbinds.push(pdu.varbinds[i]);
        }
      }

      req.responseCb(null, varbinds);
    }
  }

  var pduVarbinds = [];

  for (var i = 0; i < oids.length; i++) {
    var varbind = {
      oid: oids[i],
    };
    pduVarbinds.push(varbind);
  }

  this.simpleGet(PDU.GetNextRequestPdu, feedCb, pduVarbinds, responseCb);

  return this;
};

Session.prototype.inform = function () {
  var typeOrOid = arguments[0];
  var varbinds;
  var options = {};
  var responseCb;

  /**
   ** Support the following signatures:
   **
   **    typeOrOid, varbinds, options, callback
   **    typeOrOid, varbinds, callback
   **    typeOrOid, options, callback
   **    typeOrOid, callback
   **/
  if (arguments.length >= 4) {
    varbinds = arguments[1];
    options = arguments[2];
    responseCb = arguments[3];
  } else if (arguments.length >= 3) {
    if (arguments[1].constructor != Array) {
      varbinds = [];
      options = arguments[1];
      responseCb = arguments[2];
    } else {
      varbinds = arguments[1];
      responseCb = arguments[2];
    }
  } else {
    varbinds = [];
    responseCb = arguments[1];
  }

  function feedCb(req, message) {
    var pdu = message.PDU;
    var varbinds = [];

    if (req.pdu.varbinds.length != pdu.varbinds.length) {
      req.responseCb(new Exceptions.ResponseInvalidError('Inform OIDs do not '
          + 'match response OIDs'));
    } else {
      for (var i = 0; i < req.pdu.varbinds.length; i++) {
        if (req.pdu.varbinds[i].oid != pdu.varbinds[i].oid) {
          req.responseCb(new Exceptions.ResponseInvalidError("OID '"
              + req.pdu.varbinds[i].oid
              + "' in inform at position '" + i + "' does not match OID '"
              + pdu.varbinds[i].oid + "' in response at position '"
              + i + "'"));

          return;
        } else {
          varbinds.push(pdu.varbinds[i]);
        }
      }

      req.responseCb(null, varbinds);
    }
  }

  if (typeof typeOrOid != 'string')
    typeOrOid = '1.3.6.1.6.3.1.1.5.' + (typeOrOid + 1);

  var pduVarbinds = [
    {
      oid: '1.3.6.1.2.1.1.3.0',
      type: Constants.ObjectType.TimeTicks,
      value: options.upTime || Math.floor(process.uptime() * 100),
    },
    {
      oid: '1.3.6.1.6.3.1.1.4.1.0',
      type: Constants.ObjectType.OID,
      value: typeOrOid,
    },
  ];

  for (var i = 0; i < varbinds.length; i++) {
    var varbind = {
      oid: varbinds[i].oid,
      type: varbinds[i].type,
      value: varbinds[i].value,
    };

    pduVarbinds.push(varbind);
  }

  options.port = this.trapPort;

  this.simpleGet(PDU.InformRequestPdu, feedCb, pduVarbinds, responseCb, options);

  return this;
};

Session.prototype.onClose = function () {
  this.cancelRequests(new Error('Socket forcibly closed'));
  this.emit('close');
};

Session.prototype.onError = function (error) {
  this.emit(error);
};

Session.prototype.onMsg = function (buffer, remote) {
  var _this = this;

  // Determine version
  var reader = new Ber.Reader(buffer);

  reader.readSequence();

  var version   = reader.readInt();
  var processor = null;

  switch (version) {
    case Constants.Version1:
    case Constants.Version2c:
      processor = new V2MPM(this);
      break;
    case Constants.Version3:
      processor = new V3MPM(this);
      break;
    default:
      req.responseCb(new Exceptions.UnsupportedSecurityModel('Unknown security'
          + " model represented by the value '" + version + "'"));
      return;
  }

  // Dispatch off to version-specific processing model
  var message = processor.prepareDataElements(buffer);

  message.then(function (message) {
    var req = _this.unregisterRequest(message.PDU.id);

    // We have no request by that name, discard
    if (!req) {
      console.warn("Recieved response for invalid request ID '" + message.PDU.id + "'");
      return;
    }

    try {
      if (message.version != this.version) {
        throw new Exceptions.ResponseInvalidError("Version in request '"
            + this.version + "' does not match version in response '"
            + message.version + "'");
      } else if (message.PDU.type != Constants.PduType.GetResponse) {
        throw new Exceptions.ResponseInvalidError("Unknown PDU type '"
            + message.PDU.type + "' in response");
      }

      req.onResponse(req, message);
    } catch (error) {
      req.responseCb(error);
    }
  }).catch(function (error) {
    this.emit('error', error);
    req.resolveCb(error);
  });
};

Session.prototype.onSimpleGetResponse = function (req, message) {
  var pdu = message.PDU;

  if (pdu.errorStatus > 0) {
    var statusString = Constants.ErrorStatus[pdu.errorStatus]
        || Constants.ErrorStatus.GeneralError;
    var statusCode = Constants.ErrorStatus[statusString]
        || Constants.ErrorStatus[Constants.ErrorStatus.GeneralError];

    if (pdu.errorIndex <= 0 || pdu.errorIndex > pdu.varbinds.length) {
      req.responseCb(new Exceptions.RequestFailedError(statusString, statusCode));
    } else {
      var oid = pdu.varbinds[pdu.errorIndex - 1].oid;
      var error = new Exceptions.RequestFailedError(statusString + ': ' + oid, statusCode);

      req.responseCb(error);
    }
  } else {
    req.feedCb(req, message);
  }
};

Session.prototype.registerRequest = function (req) {
  if (!this.reqs[req.id]) {
    this.reqs[req.id] = req;

    if (this.reqCount <= 0) {
      this.dgram.ref();
    }

    this.reqCount++;
  }

  var _this = this;
  req.timer = setTimeout(function () {
    if (req.retries-- > 0) {
      _this.send(req);
    } else {
      _this.unregisterRequest(req.id);
      req.responseCb(new Exceptions.RequestTimedOutError('Request timed out'));
    }
  }, req.timeout);
};

Session.prototype.send = function (req, noWait) {
  var _this = this;

  /**
   * This is the primative parameters to be used to construct a
   * message processing model and process an outgoing request. It
   * currently only works for the v3 MPM
   **/
  var msgParams = {
    messageProcessingModel: this.version,
    securityModel: this.securityModel,
    securityName: this.securityName,
    securityLevel: this.flags,
    contextEngineID: this.contextEngineID,
    contextName: this.contextName,
    pduVersion: null,                        // the version of the PDU
    PDU: req.pdu,
    expectResponse: isConfirmed(req.pdu),
    sendPduHandle: req.id,
    destTransportDomain: null,               // OUT: destination transport domain
    destTransportAddress: null,              // OUT: destination transport address
    outgoingMessage: null,                   // OUT: the message to send
    outgoingMessageLength: null,             // OUT: and it's length
  };

  req.processor.prepareOutgoingMessage(msgParams)
  .then(function (prepared) {
    var message = prepared.outgoingMessage;
    _this.dgram.send(message, 0, message.length, req.port, _this.target, function (error, bytes) {
      if (error) {
        req.responseCb(error);
      } else {
        if (noWait) {
          req.responseCb(null);
        } else {
          _this.registerRequest(req);
        }
      }
    });
  }).catch(function (error) {
    req.responseCb(error);
  });

  return this;
};

Session.prototype.set = function (varbinds, responseCb) {
  function feedCb(req, message) {
    var pdu = message.pdu;
    var varbinds = [];

    if (req.pdu.varbinds.length != pdu.varbinds.length) {
      req.responseCb(new Exceptions.ResponseInvalidError('Requested OIDs do not '
          + 'match response OIDs'));
    } else {
      for (var i = 0; i < req.pdu.varbinds.length; i++) {
        if (req.pdu.varbinds[i].oid != pdu.varbinds[i].oid) {
          req.responseCb(new Exceptions.ResponseInvalidError("OID '"
              + req.pdu.varbinds[i].oid + "' in request at position '"
              + i + "' does not match OID '" + pdu.varbinds[i].oid
              + "' in response at position '" + i + "'"));

          return;
        } else {
          varbinds.push(pdu.varbinds[i]);
        }
      }

      req.responseCb(null, varbinds);
    }
  }

  var pduVarbinds = [];

  for (var i = 0; i < varbinds.length; i++) {
    var varbind = {
      oid: varbinds[i].oid,
      type: varbinds[i].type,
      value: varbinds[i].value,
    };

    pduVarbinds.push(varbind);
  }

  this.simpleGet(PDU.SetRequestPdu, feedCb, pduVarbinds, responseCb);

  return this;
};

Session.prototype.simpleGet = function (PduClass, feedCb, varbinds, responseCb, options) {
  var req = {};

  try {
    var id = _generateId();
    var pdu = new PduClass(id, varbinds, options);

    if (this.version >= Constants.Version3) {
      var processor = new V3MPM(this);
    } else {
      var processor = new V2MPM(this);
    }

    req = {
      id: id,
      processor: processor,
      pdu: pdu,
      responseCb: responseCb,
      retries: this.retries,
      timeout: this.timeout,
      onResponse: this.onSimpleGetResponse,
      feedCb: feedCb,
      port: (options && options.port) ? options.port : this.port,
    };

    this.send(req);
  } catch (error) {
    if (responseCb) {
      responseCb(error);
    }
  }
};

function subtreeCb(req, varbinds) {
  var done = 0;

  for (var i = varbinds.length; i > 0; i--) {
    if (!oidInSubtree(req.baseOid, varbinds[i - 1].oid)) {
      done = 1;
      varbinds.pop();
    }
  }

  if (varbinds.length > 0) {
    req.feedCb(varbinds);
  }

  if (done) {
    return true;
  }
}

Session.prototype.subtree  = function () {
  var _this = this;
  var oid = arguments[0];
  var maxRepetitions;
  var feedCb;
  var doneCb;

  if (arguments.length < 4) {
    maxRepetitions = 20;
    feedCb = arguments[1];
    doneCb = arguments[2];
  } else {
    maxRepetitions = arguments[1];
    feedCb = arguments[2];
    doneCb = arguments[3];
  }

  var req = {
    feedCb: feedCb,
    doneCb: doneCb,
    maxRepetitions: maxRepetitions,
    baseOid: oid,
  };

  this.walk(oid, maxRepetitions, subtreeCb.bind(_this, req), doneCb);

  return this;
};

function tableColumnsResponseCb(req, error) {
  if (error) {
    req.responseCb(error);
  } else if (req.error) {
    req.responseCb(req.error);
  } else {
    if (req.columns.length > 0) {
      var column = req.columns.pop();
      var _this = this;
      this.subtree(req.rowOid + column, req.maxRepetitions,
          tableColumnsFeedCb.bind(_this, req),
          tableColumnsResponseCb.bind(_this, req));
    } else {
      req.responseCb(null, req.table);
    }
  }
}

function tableColumnsFeedCb(req, varbinds) {
  for (var i = 0; i < varbinds.length; i++) {
    if (isVarbindError(varbinds[i])) {
      req.error = new Exceptions.RequestFailedError(varbindError(varbind[i]));

      return true;
    }

    var oid = varbinds[i].oid.replace(req.rowOid, '');
    if (oid && oid != varbinds[i].oid) {
      var match = oid.match(/^(\d+)\.(.+)$/);
      if (match && match[1] > 0) {
        if (!req.table[match[2]]) {
          req.table[match[2]] = {};
        }

        req.table[match[2]][match[1]] = varbinds[i].value;
      }
    }
  }
}

Session.prototype.tableColumns = function () {
  var _this = this;

  var oid = arguments[0];
  var columns = arguments[1];
  var maxRepetitions;
  var responseCb;

  if (arguments.length < 4) {
    responseCb = arguments[2];
    maxRepetitions = 20;
  } else {
    maxRepetitions = arguments[2];
    responseCb = arguments[3];
  }

  var req = {
    responseCb: responseCb,
    maxRepetitions: maxRepetitions,
    baseOid: oid,
    rowOid: oid + '.1.',
    columns: columns.slice(0),
    table: {},
  };

  if (req.columns.length > 0) {
    var column = req.columns.pop();
    this.subtree(req.rowOid + column, maxRepetitions,
        tableColumnsFeedCb.bind(_this, req),
        tableColumnsResponseCb.bind(_this, req));
  }

  return this;
};

function tableResponseCb(req, error) {
  if (error) {
    req.responseCb(error);
  } else if (req.error) {
    req.responseCb(req.error);
  } else {
    req.responseCb(null, req.table);
  }
}

function tableFeedCb(req, varbinds) {
  for (var i = 0; i < varbinds.length; i++) {
    if (isVarbindError(varbinds[i])) {
      req.error = new Exceptions.RequestFailedError(varbindError(varbind[i]));

      return true;
    }

    var oid = varbinds[i].oid.replace(req.rowOid, '');
    if (oid && oid != varbinds[i].oid) {
      var match = oid.match(/^(\d+)\.(.+)$/);
      if (match && match[1] > 0) {
        if (!req.table[match[2]]) {
          req.table[match[2]] = {};
        }

        req.table[match[2]][match[1]] = varbinds[i].value;
      }
    }
  }
}

Session.prototype.table = function () {
  var _this = this;

  var oid = arguments[0];
  var maxRepetitions;
  var responseCb;

  if (arguments.length < 3) {
    responseCb = arguments[1];
    maxRepetitions = 20;
  } else {
    maxRepetitions = arguments[1];
    responseCb = arguments[2];
  }

  var req = {
    responseCb: responseCb,
    maxRepetitions: maxRepetitions,
    baseOid: oid,
    rowOid: oid + '.1.',
    table: {},
  };

  this.subtree(oid, maxRepetitions,
      tableFeedCb.bind(_this, req),
      tableResponseCb.bind(_this, req));

  return this;
};

Session.prototype.trap = function () {
  var req = {};

  try {
    var typeOrOid = arguments[0];
    var varbinds;
    var options = {};
    var responseCb;

    /**
     ** Support the following signatures:
     **
     **    typeOrOid, varbinds, options, callback
     **    typeOrOid, varbinds, agentAddr, callback
     **    typeOrOid, varbinds, callback
     **    typeOrOid, agentAddr, callback
     **    typeOrOid, options, callback
     **    typeOrOid, callback
     **/
    if (arguments.length >= 4) {
      varbinds = arguments[1];
      if (typeof arguments[2] == 'string') {
        options.agentAddr = arguments[2];
      } else if (arguments[2].constructor != Array) {
        options = arguments[2];
      }

      responseCb = arguments[3];
    } else if (arguments.length >= 3) {
      if (typeof arguments[1] == 'string') {
        varbinds = [];
        options.agentAddr = arguments[1];
      } else if (arguments[1].constructor != Array) {
        varbinds = [];
        options = arguments[1];
      } else {
        varbinds = arguments[1];
        agentAddr = null;
      }

      responseCb = arguments[2];
    } else {
      varbinds = [];
      responseCb = arguments[1];
    }

    var pdu;
    var pduVarbinds = [];

    for (var i = 0; i < varbinds.length; i++) {
      var varbind = {
        oid: varbinds[i].oid,
        type: varbinds[i].type,
        value: varbinds[i].value,
      };

      pduVarbinds.push(varbind);
    }

    var id = _generateId();

    if (this.version == Constants.Version2c) {
      if (typeof typeOrOid != 'string') {
        typeOrOid = '1.3.6.1.6.3.1.1.5.' + (typeOrOid + 1);
      }

      pduVarbinds.unshift(
        {
          oid: '1.3.6.1.2.1.1.3.0',
          type: Constants.ObjectType.TimeTicks,
          value: options.upTime || Math.floor(process.uptime() * 100),
        },
        {
          oid: '1.3.6.1.6.3.1.1.4.1.0',
          type: Constants.ObjectType.OID,
          value: typeOrOid,
        }
      );

      pdu = new PDU.TrapV2Pdu(id, pduVarbinds, options);
    } else {
      pdu = new PDU.TrapPdu(typeOrOid, pduVarbinds, options);
    }

    var message = new V2MPM(this.version, this.community, pdu);

    req = {
      id: id,
      message: message,
      responseCb: responseCb,
      port: this.trapPort,
    };

    this.send(req, true);
  } catch (error) {
    if (req.responseCb) {
      req.responseCb(error);
    }
  }

  return this;
};

Session.prototype.unregisterRequest = function (id) {
  var req = this.reqs[id];
  if (req) {
    clearTimeout(req.timer);
    delete this.reqs[id];
    delete req.timer;
    this.reqCount--;

    if (this.reqCount <= 0) {
      this.dgram.unref();
    }

    return req;
  } else {
    return null;
  }
};

function walkCb(req, error, varbinds) {
  var done = 0;
  var oid;

  if (error) {
    if (error instanceof Exceptions.RequestFailedError) {
      if (error.status != Constants.ErrorStatus.NoSuchName) {
        req.doneCb(error);

        return;
      } else {
        // signal the version 1 walk code below that it should stop
        done = 1;
      }
    } else {
      req.doneCb(error);

      return;
    }
  }

  if (this.version == Constants.Version2c) {
    for (var i = varbinds[0].length; i > 0; i--) {
      if (varbinds[0][i - 1].type == Constants.ObjectType.EndOfMibView) {
        varbinds[0].pop();
        done = 1;
      }
    }

    if (req.feedCb(varbinds[0])) {
      done = 1;
    } else if (!done) {
      oid = varbinds[0][varbinds[0].length - 1].oid;
    }
  } else {
    if (!done) {
      if (req.feedCb(varbinds)) {
        done = 1;
      } else {
        oid = varbinds[0].oid;
      }
    }
  }

  if (done) {
    req.doneCb(null);
  } else {
    this.walk(oid, req.maxRepetitions, req.feedCb, req.doneCb, req.baseOid);
  }
}

Session.prototype.walk  = function () {
  var _this = this;
  var oid = arguments[0];
  var maxRepetitions;
  var feedCb;
  var doneCb;
  var baseOid;

  if (arguments.length < 4) {
    maxRepetitions = 20;
    feedCb = arguments[1];
    doneCb = arguments[2];
  } else {
    maxRepetitions = arguments[1];
    feedCb = arguments[2];
    doneCb = arguments[3];
  }

  var req = {
    maxRepetitions: maxRepetitions,
    feedCb: feedCb,
    doneCb: doneCb,
  };

  if (this.version == Constants.Version2c) {
    this.getBulk([oid], 0, maxRepetitions, walkCb.bind(_this, req));
  } else {
    this.getNext([oid], walkCb.bind(_this, req));
  }

  return this;
};

module.exports = Session;
