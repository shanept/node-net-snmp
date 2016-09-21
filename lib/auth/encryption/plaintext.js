var PlainText = function(options) {
    // Intentionally empty
};

PlainText.prototype.encryptData = function(buffer, data) {
    return data;
};

module.exports = PlainText;
