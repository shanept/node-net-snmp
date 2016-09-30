var no_auth = function(options) {
    // Intentionally empty
};

no_auth.prototype.generateRequestMessage = function(scopedPDU, message) {
    scopedPDU.toBuffer (message.whole);
    message.length = message.whole.buffer.length();

    return true;
};

no_auth.prototype.generateResponseMessage = function(scopedPDU, securityStateReference, message) {
    scopedPDU.toBuffer (message.whole);
    message.length = message.whole.buffer.length();

    return true;
}

module.exports = no_auth;
