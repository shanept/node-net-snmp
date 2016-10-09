var ScopedPdu = function() {
    this.contextEngineID = null;
    this.contextName = null;
    this.data = null;
};

ScopedPdu.prototype.toBuffer = function (buffer) {
    buffer.writeString (this.contextEngineID);
    buffer.writeString (this.contextName);
    this.data.toBuffer (buffer);                 // Is writeString correct here? RFC specifies type 'ANY'
};

module.exports = ScopedPdu;
