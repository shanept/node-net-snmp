var ScopedPdu = function() {
    this.contextEngineID = null;
    this.contextName = null;
    this.data = null;
};

ScopedPdu.prototype.toBuffer = function (buffer) {
    buffer.startSequence();

    buffer.writeString (this.contextEngineID);
    buffer.writeString (this.contextName);
    buffer.writeString (this.data);                 // Is writeString correct here? RFC specifies type 'ANY'

    buffer.endSequence();
};

module.exports = ScopedPdu;
