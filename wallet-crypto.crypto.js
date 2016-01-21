'use strict';

var crypto = require('crypto');

var Iso10126 = {

  pad: function (dataBytes, nBytesPerBlock) {
    var nPaddingBytes = nBytesPerBlock - dataBytes.length % nBytesPerBlock
      , paddingBytes  = crypto.randomBytes(nPaddingBytes - 1)
      , endByte       = new Buffer([ nPaddingBytes ]);
    return Buffer.concat([ dataBytes, paddingBytes, endByte ]);
  },

  unpad: function (dataBytes) {
    var endByteIndex  = dataBytes.length - 1
      , nPaddingBytes = dataBytes[endByteIndex];
    return dataBytes.slice(0, -nPaddingBytes);
  }

};

function encrypt(data, password, iterations) {
  var SALT_BYTES  = 16
    , KEY_BIT_LEN = 256
    , AES_CBC     = 'aes-256-cbc';

  var iv    = crypto.randomBytes(SALT_BYTES)
    , salt  = iv.toString('binary')
    , key   = crypto.pbkdf2Sync(password, salt, iterations, KEY_BIT_LEN / 8);

  var cipher = crypto.createCipheriv(AES_CBC, key, iv);
  cipher.setAutoPadding(false);

  var dataBuffer  = new Buffer(data, 'utf8')
    , dataPadded  = Iso10126.pad(dataBuffer, KEY_BIT_LEN / 8);

  var encrypted = cipher.update(dataPadded, '_', 'hex') + cipher.final('hex')
    , payload   = iv.toString('hex') + encrypted;

  return new Buffer(payload, 'hex').toString('base64');
}

function decryptAes(data, password, iterations, options) {
  options = options || {};
  var SALT_BYTES  = 16
    , KEY_BIT_LEN = 256
    , AES_CBC     = 'aes-256-cbc';

  var dataHex = new Buffer(data, 'base64').toString('hex')
    , iv      = new Buffer(dataHex.slice(0, SALT_BYTES * 2), 'hex')
    , salt    = iv.toString('binary')
    , payload = dataHex.slice(SALT_BYTES * 2)
    , key     = crypto.pbkdf2Sync(password, salt, iterations, KEY_BIT_LEN / 8);

  var decipher = crypto.createDecipheriv(AES_CBC, key, iv);
  decipher.setAutoPadding(false);

  var decryptedBase64 = decipher.update(payload, 'hex', 'base64') + decipher.final('base64')
    , decryptedBytes  = new Buffer(decryptedBase64, 'base64')
    , unpaddedBytes   = (options.padding || Iso10126).unpad(decryptedBytes);

  return unpaddedBytes.toString('utf8');
}

module.exports = {
  encrypt: encrypt,
  decryptAes: decryptAes
};
