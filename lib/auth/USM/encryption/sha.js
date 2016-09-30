var SHA = function(options) {
    
};

SHA.prototype.encryptData = function(key, data) {
    return {
        statusInformation: true,
        encryptedData: data,
        privParameters: parameters
    };
};

module.exports = SHA;
