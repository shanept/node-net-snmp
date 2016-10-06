var Constants = require("../../../constants");
var Exceptions = require("../../../exceptions");
var TimeWindow = require("../../TimeWindow");
var UsmSecurityParameters = require("./usm-security-parameters");
var HMAC_MD5_96 = require("./authentication/md5");
var HMAC_SHA_96 = require("./authentication/sha");
var Ber = require("asn1").Ber;

var USM = function(session) {
    var config  = session.UsmOptions;

    if (!config) {
        throw new Error('No configuration provided to User-based Security Model.');
    }

    config.authKey = config.authKey || '';
    config.privKey = config.privKey || '';

    this.session = session;
    this.config  = config;
};

USM.prototype.generateRequestMessage = function(options) {
    options.securityStateReference = null;
    return this.generateResponseMessage(options);
};

USM.prototype.generateResponseMessage = function(options) {
    var securityParameters = new UsmSecurityParameters,
        must_encrypt = options.securityLevel & Constants.BitwiseFlags.Priv,
        must_authenticate = options.securityLevel & Constants.BitwiseFlags.Auth,
        authModel = null,
        privModel = null;

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
    if (securityStateReference !== null) {
        throw new Error("Not yet implemented");     // requires an LCD
    } else if (false != options.securityName) {
        // Currently, we just use the settings provided by this.config
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

        authModel = this._getAuthModel(usmUserAuthProtocol);
        privModel = this._getPrivModel(usmUserPrivProtocol);

        /**
         * Localize Auth and Priv keys
         */
        var usmUserAuthKeyLocalized = null,
            usmUserPrivKeyLocalized = null;
    } else {
        throw new Error('Expected username for the User-based Security Model - none provided.');
    }

    /**
     * 3.1.2 - Verify the selected privacy protocol is supported
     */
    if (!must_encrypt) {
        options.privModel = 'plain';
    } else if (!config.privModel) {
        throw new Error('Privacy requested, without privacy parameters!');
    } else if (Constants.PrivTypes.indexOf(config.privModel) === -1) {
        throw new Exceptions.UnsupportedSecurityLevel(
            'Unsupported Privacy type: "' + config.privModel + '"'
        );
    }

    /**
     * 3.1.3 - Verify the selected authentication protocol is supported
     */
    if (must_authenticate && Constants.AuthTypes.indexOf(config.authModel) === -1) {
        throw new Exceptions.UnsupportedSecurityLevel(
            'Unsupported Authentication type: "' + config.authModel + '"'
        );
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
    var scopedPDUData = new Ber.Writer ();
    scopedPDU.toBuffer (scopedPDUData);

    if (must_encrypt) {
        scopedPDUData = this._performEncryption(scopedPDUData, usmUserPrivKeyLocalized, securityParameters);
    } else {
        securityParameters.msgPrivacyParameters = '';
    }

    // Should we extract here, or further down?
    scopedPDUData = scopedPDUData.buffer;

    /**
     * 3.1.5 - Add securityEngineID to msgAuthoritativeEngineId
     *
     * Put securityEngineID into msgAuthoritativeEngineId. A zero-length ID
     * is if unknown, as it will result in the remote engine returning a
     * report PDU with the value of its Engine ID.
     */
    securityParameters.msgAuthoritativeEngineId = this.session.engineID;

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
        // To come from the LCD
        // 3.6(a) - Authenticate
    } else if (this.securityStateReference !== null) {
        // 3.6(b) - Response
        securityParameters.msgAuthoritativeEngineBoots = this.timeWindow.getBoots();
        securityParameters.msgAuthoritativeEngineTime  = this.timeWindow.getTime();
    } else {
        // 3.6(c) - Request
        securityParameters.msgAuthoritativeEngineBoots = 0;
        securityParameters.msgAuthoritativeEngineTime  = 0;
    }

    /**
     * 3.1.7 - Add username to msgUserName
     */
    securityParameters.msgUserName = this.username;

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
        this._performAuthentication(scopedPDU, usmUserAuthKeyLocalized, securityParameters);
    } else {
        securityParameters.msgAuthenticationParameters = '';
    }

    return {
        statusInformation: true,
        securityParameters: securityParameters,
        scopedPDU: scopedPDU
    };
};

USM.prototype._getAuthModel = function(protocol) {
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

USM.prototype._performEncryption = function(scopedPDU, key, securityParameters) {
    switch (this.config.privModel) {
        // ..
    }

    // ->                                       key,       pdu
    var encryption = new this[encryptionModule](key, scopedPDU);

    if (!encryption.statusInformation) {
        throw new Exceptions.EncryptionError("The encryption mechanism failed.");
    }

    securityParameters.msgPrivacyParameters = encryption.privParameters;
    return encryption.encryptedData;
};

USM.prototype._performAuthentication = function(scopedPDU, key, securityParameters) {
    throw new Error('Not yet implemented');

    var params = auth.authenticateOutgoingMsg(key, securityParameters);

    if (!auth.statusInformation) {
        throw new Exceptions.AuthenticationFailure("The message could not be authenticated.");
    }

    securityParameters.msgAuthenticationParameters = auth.authParameters;
};

module.exports = USM;
