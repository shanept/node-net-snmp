var MD5 = function(options) {
    
};

MD5.prototype.encryptData = function(key, data, parameters) {
    return {
        statusInformation: true,
        encryptedData: data,
        privParameters: parameters
    };
};

module.exports = MD5;
