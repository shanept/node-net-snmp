
// Copyright 2013 Stephen Vickers <stephen.vickers.sv@gmail.com>

var Constants = require ("./constants");
var Exceptions = require ("./exceptions");
var Session = require("./session");
var RequestMessage = require("./request");
var V3RequestMessage = require("./v3request");
var HeaderData = require("./header");
var ResponseMessage = require("./response");

/*****************************************************************************
 ** Exports
 **/

exports.Session = Session;

exports.createSession = function (target, community, options) {
	if (options || !(community && community.version)) {
		return new Session (target, community, options);
	} else {
		// community becomes our options in this case
		return new Session (target, null, community);
	}
};

exports.isVarbindError = isVarbindError;
exports.varbindError = varbindError;

exports.Version1 = Constants.Version1;
exports.Version2c = Constants.Version2c;
exports.Version3 = Constants.Version3;

exports.ErrorStatus = Constants.ErrorStatus;
exports.TrapType = Constants.TrapType;
exports.ObjectType = Constants.ObjectType;
exports.SecurityModel = Constants.SecurityModel;
exports.Flags = Constants.Flags;

exports.ResponseInvalidError = Exceptions.ResponseInvalidError;
exports.RequestInvalidError = Exceptions.RequestInvalidError;
exports.RequestFailedError = Exceptions.RequestFailedError;
exports.RequestTimedOutError = Exceptions.RequestTimedOutError;

/**
 ** We've added this for testing.
 **/
exports.ObjectParser = {
	readInt: readInt,
	readUint: readUint
};
