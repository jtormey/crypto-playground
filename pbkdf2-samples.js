'use strict';

var pbkdf2_sha256 = require('pbkdf2-sha256')
  , pbkdf2        = require('pbkdf2')
  , CryptoJS      = require('crypto-js')
  , sjcl          = require('sjcl')
  , crypto        = require('crypto');

var passwordStretchers = {

  crypto_lib: function (password, salt, iterations, keySize) {
    return crypto.pbkdf2Sync(password, salt, iterations, keySize / 8, 'sha1');
  },

  pbkdf2_lib: function (password, salt, iterations, keySize) {
    var derivedKey = pbkdf2.pbkdf2Sync(password, salt.toString('binary'), iterations, keySize/8, 'sha1');
    return CryptoJS.enc.Hex.parse(derivedKey.toString('hex'));
  },

  sjcl_lib: function (password, salt, iterations, keySize) {
    var hmacSHA1 = function (key) {
      var hasher = new sjcl.misc.hmac(key, sjcl.hash.sha1);
      this.encrypt = hasher.encrypt.bind(hasher);
    };
    salt = sjcl.codec.hex.toBits(salt.toString('hex'));
    var stretched = sjcl.misc.pbkdf2(password, salt, iterations, keySize, hmacSHA1);
    return CryptoJS.enc.Hex.parse(sjcl.codec.hex.fromBits(stretched));
  },

  // Omitted, for being slow asf
  // CryptoJS_lib: function (password, salt, iterations, keySize) {
  //   var options = { keySize: keySize/32, iterations: iterations};
  //   var stretched = CryptoJS.PBKDF2(password, salt, options);
  //   return stretched;
  // },

  // Omitted, for being SHA256
  // pbkdf2_sha256_lib: function (password, salt, iterations, keySize) {
  //   return pbkdf2_sha256(password, salt.toString('hex'), iterations, keySize / 8);
  // }

};

module.exports = passwordStretchers;
