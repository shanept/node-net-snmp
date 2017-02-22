var util = require('util');

function ResponseInvalidError(message) {
  this.name = 'ResponseInvalidError';
  this.message = message;
  Error.captureStackTrace(this, ResponseInvalidError);
}

function RequestInvalidError(message) {
  this.name = 'RequestInvalidError';
  this.message = message;
  Error.captureStackTrace(this, RequestInvalidError);
}

function RequestFailedError(message, status) {
  this.name = 'RequestFailedError';
  this.message = message;
  this.status = status;
  Error.captureStackTrace(this, RequestFailedError);
}

function RequestTimedOutError(message) {
  this.name = 'RequestTimedOutError';
  this.message = message;
  Error.captureStackTrace(this, RequestTimedOutError);
}

function UnsupportedSecurityLevel(message) {
  this.name = 'UnsupportedSecurityLevel';
  this.message = message;
  Error.captureStackTrace(this, UnsupportedSecurityLevel);
}

function UnsupportedSecurityModel(message) {
  this.name = 'UnsupportedSecurityModel';
  this.message = message;
  Error.captureStackTrace(this, UnsupportedSecurityModel);
}

function EncryptionError(message) {
  this.name = 'EncryptionError';
  this.message = message;
  Error.captureStackTrace(this, EncryptionError);
}

function NotInTimeWindow(message) {
  this.name = 'NotInTimeWindow';
  this.message = message;
  Error.captureStackTrace(this, NotInTimeWindow);
}

util.inherits(ResponseInvalidError, Error);
util.inherits(RequestInvalidError, Error);
util.inherits(RequestFailedError, Error);
util.inherits(RequestTimedOutError, Error);
util.inherits(UnsupportedSecurityLevel, Error);
util.inherits(UnsupportedSecurityModel, Error);
util.inherits(EncryptionError, Error);
util.inherits(NotInTimeWindow, Error);

module.exports = {
  ResponseInvalidError: ResponseInvalidError,
  RequestInvalidError: RequestInvalidError,
  RequestFailedError: RequestFailedError,
  RequestTimedOutError: RequestTimedOutError,
  UnsupportedSecurityLevel: UnsupportedSecurityLevel,
  UnsupportedSecurityModel: UnsupportedSecurityModel,
  EncryptionError: EncryptionError,
  NotInTimeWindow: NotInTimeWindow,
};
