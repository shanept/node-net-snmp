var Constants = require("../../../constants");
var Exceptions = require("../../../exceptions");
var TimeWindow = require("../../TimeWindow");
var UsmSecurityParameters = require("./UsmSecurityParameters");
var HMAC_MD5_96 = require("./authentication/md5");
var HMAC_SHA_96 = require("./authentication/sha");
var Ber = require("asn1").Ber;
var PDU = require("../../../pdu.js");

var USM = function(messageProcessingModel) {
    var config  = messageProcessingModel.session.UsmOptions;

    if (!config) {
        throw new Error('No configuration provided to User-based Security Model.');
    }

    config.authKey = config.authKey || '';
    config.privKey = config.privKey || '';

    this.mpm     = messageProcessingModel;
    this.session = messageProcessingModel.session;
    this.config  = config;
};

USM.prototype.generateRequestMsg = function(options) {
    options.securityStateReference = null;
    return this.generateResponseMsg(options);
};

USM.prototype.generateResponseMsg = function(options) {
    var me = this,
        securityParameters = new UsmSecurityParameters,
        scopedPDUData = new Ber.Writer (),
        must_encrypt = options.securityLevel & Constants.BitwiseFlags.Priv,
        must_authenticate = options.securityLevel & Constants.BitwiseFlags.Auth,
        authModel = null,
        privModel = null;

    return new Promise(function(resolve, reject) {
        /**
         * 3.1.1
         *  a) If a securityStateReference is passed (ie. not null), extract
         *     information regarding the user from the cachedSecurityData,
         *     this information may now be cleared from cache. Set the
         *     securityEngineId to that of the local snmpEngineId,
         *     and securityLevel to that passed in options.
         *
         *  b) Based on the securityName at the specified securityEngineID,
         *     extract user information from the LCD. If information is
         *     absent from the LCD, an unknownSecurityName exception
         *     is thrown.
         */
        if (options.securityStateReference !== null) {
            reject (new Error("Not yet implemented"));     // requires an LCD
        } else if (false != options.securityName) {
            // Currently, we just use the settings provided by me.config
            var _usmTable = {
                usmUserEngineID: options.securityEngineId,
                usmUserName: options.securityName,
                usmUserSecurityName: options.securityName,
                usmUserCloneFrom: '0.0',
                usmUserAuthProtocol: options.config.authModel,
                usmUserAuthKeyChange: '',
                usmUserOwnAuthKeyChange: '',
                usmUserPrivProtocol: options.config.privModel,
                usmUserPrivKeyChange: '',
                usmUserOwnPrivKeyChange: '',
                usmUserPublic: '',
                usmUserStorageType: Constants.StorageType.readOnly,
                usmUserStatus: undefined        // Don't know what to set it to... It's not important here anyway.
            };

            var usmUserName = _usmTable.usmUserName,
                usmUserAuthProtocol = _usmTable.usmUserAuthProtocol,
                usmUserPrivProtocol = _usmTable.usmUserPrivProtocol;

            authModel = me._getAuthModel(usmUserAuthProtocol);
            privModel = me._getPrivModel(usmUserPrivProtocol);

            /**
             * Localize Auth and Priv keys
             */
            var usmUserAuthKeyLocalized = null,
                usmUserPrivKeyLocalized = null;
        } else {
            // We are performing discovery. Go ahead.
            var usmUserName = '',
                usmUserAuthProtocol = '',
                usmUserPrivProtocol = '';
            authModel = null;
            privModel = null;
        }

        var usmUserOptions = {
            usmUserName: usmUserName,
            usmUserAuthProtocol: authModel,
            usmUserPrivProtocol: privModel,
            usmUserAuthKeyLocalized: usmUserAuthKeyLocalized,
            usmUserPrivKeyLocalized: usmUserPrivKeyLocalized
        };

        /**
         * 3.1.2 - Verify the selected privacy protocol is supported
         */
        if (!must_encrypt) {
            options.privModel = 'plain';
        } else if (!config.privModel) {
            reject (new Error('Privacy requested, without privacy parameters!'));
        } else if (Constants.PrivTypes.indexOf(config.privModel.toString()) === -1) {
            reject (new Exceptions.UnsupportedSecurityLevel(
                'Unsupported Privacy type: "' + config.privModel + '"'
            ));
        }

        /**
         * 3.1.3 - Verify the selected authentication protocol is supported
         */
        if (must_authenticate && Constants.AuthTypes.indexOf(config.authModel.toString()) === -1) {
            reject (new Exceptions.UnsupportedSecurityLevel(
                'Unsupported Authentication type: "' + config.authModel + '"'
            ));
        }

        /**
         * 3.1.4 - Protect scopedPDU from disclosure
         *
         *  a) If the securityLevel indicates that the message payload must be
         *     protected against disclosure, it must be encrypted as per the
         *     selected privacy protocol.
         *
         *     If the privacy protocol fails, it will throw an exception that will
         *     bubble up the call stack. If the protocol indicates successful
         *     encryption, the returned privacy parameters shall be copied
         *     into msgPrivacyParameters.
         *
         *     The above is implemented in the _performEncryption method.
         *
         *  b) If the securityLevel indicates the message should not be protected
         *     from disclosure, we simply assign a zero-length string to the
         *     value of msgPrivacyParameters.
         */
        options.scopedPDU.toBuffer (scopedPDUData);
        // Extract the buffer value from scopedPDUData
        scopedPDUData = scopedPDUData.buffer;

        if (must_encrypt) {
            try {
                scopedPDUData = me._performEncryption (scopedPDUData, usmUserPrivKeyLocalized, securityParameters);
            } catch (error) {
                reject (error);
            }
        } else {
            securityParameters.msgPrivacyParameters = '';
        }

        /**
         * 3.1.5 - Add securityEngineID to msgAuthoritativeEngineId
         *
         * Put securityEngineID into msgAuthoritativeEngineId. A zero-length ID
         * is if unknown, as it will result in the remote engine returning a
         * report PDU with the value of its Engine ID.
         */
        securityParameters.msgAuthoritativeEngineId = me.session.engineID;

        /**
         * 3.1.6 - Time Window
         *
         * The values of snmpEngineBoots and snmpEngineTime must be determined,
         * as per the outlines below. Once determined, they are copied into
         * the msgAuthoritativeEngineBoots and msgAuthoritativeEngineTime
         * fields of securityParameters.
         *
         *  a) If the securityLevel indicates the message must be authenticated,
         *     the corresponding values of snmpEngineBoots and snmpEngineTime
         *     from the LCD are used, corresponding to the securityEngineID.
         *
         *  b) If this is a response or report message, values of snmpEngineBoots
         *     and snmpEngineTime from the local engine are used.
         *
         *  c) If this is a request message, then a zero value is used for both
         *     snmpEngineBoots and snmpEngineTime.
         */
        if (must_authenticate) {
            console.log('Must authenticate');
            // To come from the LCD - requires discovery?
            try {
                me._performDiscovery (options, function () {
                    _afterTimeWindowCb (usmUserOptions, resolve, reject);
                });
            } catch (error) {
                reject(error);
            }
            return;
            // 3.6(a) - Authenticate
        } else if (options.securityStateReference !== null) {
            console.log('No - this is a response!');
            // 3.6(b) - Response
            securityParameters.msgAuthoritativeEngineBoots = me.timeWindow.getBoots();
            securityParameters.msgAuthoritativeEngineTime  = me.timeWindow.getTime();
        } else {
            console.log('No discovery!');
            // 3.6(c) - Request
            securityParameters.msgAuthoritativeEngineBoots = 0;
            securityParameters.msgAuthoritativeEngineTime  = 0;
        }

        _afterTimeWindowCb (usmUserOptions, resolve, reject);
    });

    function _afterTimeWindowCb (usmUserOptions, resolve, reject) {
        /**
         * 3.1.7 - Add username to msgUserName
         */
        securityParameters.msgUserName = usmUserOptions.usmUserName;

        /**
         * Build structured message
         *
         * This is as far as we can go without buffering our structured message.
         * Build the message into a buffer so we may authenticate the message
         * contents, then return it.
         */
        var wholeMsg = me._buildWholeMsg(
                options.globalData, securityParameters, scopedPDUData
            ),
            authenticatedWholeMsg = '';

        /**
         * 3.1.8 - Authentication
         *
         *  a) If the securityLevel indicates the message must be authenticated,
         *     the message is passed to the specified authentication protocol.
         *
         *     If the authentication module fails, it will throw an exception that
         *     will bubble up the call stack. If the module succeeds, then the
         *     authenticatedWholeMsg represents the authenticated message.
         *
         *     The above is implemented in the _performAuthentication method.
         *
         *  b) If the securityLevel specifies the message not be authenticated,
         *     a zero-length string is copied to msgAuthenticationParameters
         *     and the original message is used.
         */
        if (must_authenticate) {
            try {
                authenticatedWholeMsg = me._performAuthentication (wholeMsg, usmUserAuthKeyLocalized, securityParameters);
            } catch (error) {
                reject (error);
                return;
            }
        } else {
            securityParameters.msgAuthenticationParameters = '';
            authenticatedWholeMsg = wholeMsg;
        }

        resolve ({
            statusInformation: true,
            securityParameters: securityParameters,
            wholeMsg: wholeMsg
        });
    }
};

USM.prototype._buildWholeMsg = function(header, securityParameters, scopedPDUData) {
    var writer = new Ber.Writer ();

    writer.startSequence ();

    // SNMP v3 version identifier
    writer.writeInt (Constants.Version3);

    // SNMP v3 header
    header.toBuffer (writer);

    // USM Security Parameters header
    securityParameters.toBuffer (writer);

    // scopedPDUData (encrypted or plain)
    writer.writeBuffer (scopedPDUData, 4);

    writer.endSequence();

    return writer.buffer;
};

USM.prototype._getAuthModel = function (protocol) {
    var model = null;

    switch (protocol) {
        case Constants.AuthTypes.MD5:
            model = new HMAC_MD5_96;
            break;
        case Constants.AuthTypes.SHA:
            model = new HMAC_SHA_96;
            break;
        case 'plain':
        default:
            throw new Error.UnsupportedSecurityLevel('Unsupported Authentication Type: ' + protocol);
    }

    return model;
};

USM.prototype._getPrivModel = function(protocol) {
    var model = null;

    switch (protocol) {
        case Constants.PrivTypes.DES:
//            model = new *DES*;
            break;
        case 'plain':
        default:
            throw new Error.UnsupportedSecurityLevel('Unsupported Privacy Type: ' + protocol);
    }

    return model;
};

USM.prototype._localizeKey = function(hash, password) {
    return hash.localizeKey(hash.hashPassphrase(password), this.securityEngineId);
};

USM.prototype._performEncryption = function(scopedPDUData, key, securityParameters) {
    switch (this.config.privModel) {
        // ..
    }

    // ->                                       key,       pdu
    var encryption = new this[encryptionModule](key, scopedPDUData);

    if (!encryption.statusInformation) {
        throw new Exceptions.EncryptionError("The encryption mechanism failed.");
    }

    securityParameters.msgPrivacyParameters = encryption.privParameters;
    return encryption.encryptedData;
};

USM.prototype._performAuthentication = function(wholeMsg, key, securityParameters) {
    throw new Error('Not yet implemented');

    var params = auth.authenticateOutgoingMsg(key, wholeMsg);

    if (!params.statusInformation) {
        throw new Exceptions.AuthenticationFailure("The message could not be authenticated.");
    }

    securityParameters.msgAuthenticationParameters = params.authParameters;

    return params.authenticatedWholeMsg;
};

/**
 * Engine discovery
 *
 * Discovery allows a non-authoritative engine to discover the ID of an
 * authoritative engine on an SNMP network. The authoritative engine
 * ID must be known before communication may proceed.
 *
 * The ID is discovered by generating a request with a security level of
 * noAuthNoPriv, an empty msgUserName and msgAuthoritativeEngineID and
 * an empty varBindList.
 *
 * The response will be a report message containing the snmpEngineID of
 * the authoritative engine, as the value of msgAuthoritativeEngineID
 * in msgSecurityParameters. It contains a report PDU with the
 * usmStatsUnknownEngineIDs counter in the varBindList.
 *
 * If authenticated communication is required, then the discovery process
 * must also establish time synchronization with the authoritative snmp
 * engine, by sending an authenticated request message with the value
 * of msgAuthoritativeEngineID set to the snmpEngineID discovered
 * in the previous step, msgAuthoritativeEngineBoots set to 0,
 * and msgAuthoritativeEngineTime set to 0.
 *
 * For an authenticated Request message, a valid userName must be used in
 * the userName field. The response shall be a Report message, with the
 * values of the authoritative SNMP engine's snmpEngineBoots value,
 * and snmpEngineTime value. The varBindList shall also contain
 * the value of the usmStatsNotInTimeWindows counter.
 */
USM.prototype._performDiscovery = function(options, callback) {
    var id = null; // random ID

    // Surely we can do better than this?
    var fakeSession = {};
    Object.assign(fakeSession, this.session);
    fakeSession.engineID = '';

    var processingModelPrimativeParameters = {
        messageProcessingModel: this.mpm.options.version,
        securityModel: Constants.SecurityModel.USM,
        securityName: '',
        securityLevel: Constants.Flags.noAuthNoPriv,
        contextEngineID: '',
        contextName: '',
        pduVersion: null,				// the version of the PDU
        PDU: pdu,
        expectResponse: true,
        sendPduHandle: id,
        destTransportDomain: null,		// OUT: destination transport domain
        destTransportAddress: null,		// OUT: destination transport address
        outgoingMessage: null,			// OUT: the message to send
        outgoingMessageLength: null		// OUT: and it's length
    };

    var pdu = new PDU.GetRequestPdu (id, varbinds, options)

    var mpm = new this.mpm.constructor(fakeSession, processingModelPrimativeParameters);     // This is awfully hacky... Is there a better way?
    var message = mpm.prepareOutgoingMessage(pdu);

    // On error, it can just bubble up
    message.then(function(data) {
        // Now what?
        console.log(data);
    });
};

module.exports = USM;
