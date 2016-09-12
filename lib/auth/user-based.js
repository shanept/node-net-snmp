var Constants = require("../constants");

var USM = function(options) {
    this.engineId = options.engineId;
    this.boots = options.boots;
    this.time = options.time;

    if (!options.username)
        throw new Error('Expected username for the User-based Security Model - none provided.');

    this.username = options.username;
    this.auth = options.authParams;
    this.priv = options.privParams;
};

USM.prototype.generateRequestMessage = function(buffer, message)
    
};

module.exports = USM;
