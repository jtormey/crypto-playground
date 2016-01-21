'use strict';

var crypto = require('crypto');

function encrypt(data, password, iterations) {
  var SALT_BYTES  = 16
    , KEY_BIT_LEN = 256
    , AES_CBC     = 'aes-256-cbc';

  var iv    = crypto.randomBytes(SALT_BYTES)
    , salt  = iv.toString('binary')
    , key   = crypto.pbkdf2Sync(password, salt, iterations, KEY_BIT_LEN / 8);

  var cipher = crypto.createCipheriv(AES_CBC, key, iv);

  data = new Buffer(data, 'utf8');
  var encrypted = cipher.update(data, '_', 'hex') + cipher.final('hex')
    , payload   = iv.toString('hex') + encrypted;

  return new Buffer(payload, 'hex').toString('base64');
}

function decryptAes(data, password, iterations) {
  var SALT_BYTES  = 16
    , KEY_BIT_LEN = 256
    , AES_CBC     = 'aes-256-cbc';

  var dataHex = new Buffer(data, 'base64').toString('hex')
    , iv      = new Buffer(dataHex.slice(0, SALT_BYTES * 2), 'hex')
    , salt    = iv.toString('binary')
    , payload = dataHex.slice(SALT_BYTES * 2)
    , key     = crypto.pbkdf2Sync(password, salt, iterations, KEY_BIT_LEN / 8);

  var decipher = crypto.createDecipheriv(AES_CBC, key, iv);

  var decrypted = decipher.update(payload, 'hex', 'utf8');
  return decrypted + decipher.final('utf8');
}

module.exports = {
  encrypt: encrypt,
  decryptAes: decryptAes
};
