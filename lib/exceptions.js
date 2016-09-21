var util = require ("util");

function ResponseInvalidError (message) {
	this.name = "ResponseInvalidError";
	this.message = message;
	Error.captureStackTrace(this, ResponseInvalidError);
}
util.inherits (ResponseInvalidError, Error);

function RequestInvalidError (message) {
	this.name = "RequestInvalidError";
	this.message = message;
	Error.captureStackTrace(this, RequestInvalidError);
}
util.inherits (RequestInvalidError, Error);

function RequestFailedError (message, status) {
	this.name = "RequestFailedError";
	this.message = message;
	this.status = status;
	Error.captureStackTrace(this, RequestFailedError);
}
util.inherits (RequestFailedError, Error);

function RequestTimedOutError (message) {
	this.name = "RequestTimedOutError";
	this.message = message;
	Error.captureStackTrace(this, RequestTimedOutError);
}
util.inherits (RequestTimedOutError, Error);

function UnsupportedSecurityLevel (message) {
	this.name = "UnsupportedSecurityLevel";
	this.message = message;
	Error.captureStackTrace(this, UnsupportedSecurityLevel);
}
util.inherits (UnsupportedSecurityLevel, Error);

module.exports = {
    ResponseInvalidError: ResponseInvalidError,
    RequestInvalidError: RequestInvalidError,
    RequestFailedError: RequestFailedError,
    RequestTimedOutError: RequestTimedOutError,
	UnsupportedSecurityLevel: UnsupportedSecurityLevel
};
