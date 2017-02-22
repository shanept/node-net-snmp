var PlainText = function (options) {
  // Intentionally empty
};

PlainText.prototype.encryptData = function (key, data) {
  return {
    statusInformation: true,
    encryptedData: data,
    privParameters: '',
  };
};

module.exports = PlainText;
