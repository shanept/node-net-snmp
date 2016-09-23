var PlainText = function(options) {
    // Intentionally empty
};

PlainText.prototype.encryptData = function(key, data, parameters) {
    return {
        statusInformation: true,
        encryptedData: data,
        privParameters: parameters
    };
};

module.exports = PlainText;
