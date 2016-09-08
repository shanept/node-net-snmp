var no_auth = function(options) {
    // Intentionally empty
};

no_auth.prototype.generateRequestMessage = function(buffer, message) {
    buffer.startSequence();

    // Just add PDU straight to the message
    message.toBuffer (buffer);

    buffer.endSequence();
};

module.exports = no_auth;
