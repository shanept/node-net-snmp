var ScopedPdu = function () {
  this.contextEngineID = null;
  this.contextName = null;
  this.data = null;
};

ScopedPdu.prototype.toBuffer = function (buffer) {
  buffer.writeString(this.contextEngineID);
  buffer.writeString(this.contextName);

  // Is writeString correct here? RFC specifies type 'ANY'
  this.data.toBuffer(buffer);
};

ScopedPdu.prototype.fromBuffer = function (buffer) {
};

module.exports = ScopedPdu;
