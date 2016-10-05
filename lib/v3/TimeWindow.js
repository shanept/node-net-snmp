var Constants = require('./constants');
var Exceptions = require('./exceptions');

var TimeWindow = function(engineID) {
    this.snmpEngineId    = engineID;
    this.snmpEngineBoots = 0;
    this.snmpEngineTime  = 0;
    this.latestReceivedEngineTime = 0;
};

TimeWindow.prototype._calculate = function() {
    var date = new Date(),
        time = date.now() - this.snmpEngineTime;

    if (time > Constants.maxInt) {
        this.snmpEngineBoots++;
        this.snmpEngineTime += Constants.maxInt;
        time -= Constants.maxInt;
    }

    return {
        boots: this.snmpEngineBoots,
        time:  time
    };
};

TimeWindow.prototype.getEngineId = function() {
    return this.snmpEngineId;
};

TimeWindow.prototype.getBoots = function() {
    return this._calculate().boots;
};

TimeWindow.prototype.getTime = function() {
    return this._calculate().time;
};

TimeWindow.prototype.getLastReceivedTime = function() {
    return this.latestReceivedEngineTime;
};

TimeWindow.prototype.update = function(boots, time) {
    if (boots > Constants.maxInt) {
        throw new Error("Invalid snmpEngineBoots value (greater than " + Constants.maxInt + ").");
    }

    if (time > Constants.maxInt) {
        throw new Error("Invalid snmpEngineTime value (greater than " + Constants.maxInt + ").");
    }

    var date = new Date();

    this.latestReceivedEngineTime = time;
    this.snmpEngineBoots = boots;

    // Rather than storing the current value of snmpEngineTime, we will store
    //  the local timestamp at which it would have been 'zero'. In retrieval,
    //  we will calculate the value again. This means we don't need to
    //  increment the value every second.
    this.snmpEngineTime  = date.now() - time;
};

modules.export = TimeWindow;
