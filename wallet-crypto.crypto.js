'use strict';

var crypto  = require('crypto')
  , assert  = require('assert');

var SUPPORTED_ENCRYPTION_VERSION = 3;

var AES = {
  CBC : 'aes-256-cbc',
  OFB : 'aes-256-ofb'
};

var NoPadding = {
  /*
  *   Literally does nothing...
  */

  pad: function (dataBytes) {
    return dataBytes;
  },

  unpad: function (dataBytes) {
    return dataBytes;
  }
};

var ZeroPadding = {
  /*
  *   Fills remaining block space with 0x00 bytes
  *   May cause issues if data ends with any 0x00 bytes
  */

  pad: function (dataBytes, nBytesPerBlock) {
    var nPaddingBytes = nBytesPerBlock - dataBytes.length % nBytesPerBlock
      , zeroBytes = new Buffer(nPaddingBytes).fill(0x00);
    return Buffer.concat([ dataBytes, zeroBytes ]);
  },

  unpad: function (dataBytes) {
    var unpaddedHex = dataBytes.toString('hex').replace(/(00)+$/, '');
    return new Buffer(unpaddedHex, 'hex');
  }
};

var Iso10126 = {
  /*
  *   Fills remaining block space with random byte values, except for the
  *   final byte, which denotes the byte length of the padding
  */

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

var Iso97971 = {
  /*
  *   Fills remaining block space with 0x00 bytes following a 0x80 byte,
  *   which serves as a mark for where the padding begins
  */

  pad: function (dataBytes, nBytesPerBlock) {
    var withStartByte = Buffer.concat([ dataBytes, new Buffer([ 0x80 ]) ]);
    return ZeroPadding.pad(withStartByte, nBytesPerBlock);
  },

  unpad: function (dataBytes) {
    var zeroBytesRemoved = ZeroPadding.unpad(dataBytes);
    return zeroBytesRemoved.slice(0, zeroBytesRemoved.length - 1);
  }
};

function decryptSecretWithSecondPassword(secret, password, sharedKey, pbkdf2_iterations) {
  assert(secret, 'secret missing');
  assert(password, 'password missing');
  assert(sharedKey, 'sharedKey missing');
  assert(pbkdf2_iterations, 'pbkdf2_iterations missing');

  var result = decryptAes(secret, sharedKey + password, pbkdf2_iterations);
  assert(result, 'Second password decryption failure');
  return result;
}

function encryptSecretWithSecondPassword(base58, password, sharedKey, pbkdf2_iterations) {
  assert(base58, 'base58 missing');
  assert(password, 'password missing');
  assert(sharedKey, 'sharedKey missing');
  assert(pbkdf2_iterations, 'pbkdf2_iterations missing');
  var base64 = new Buffer(base58, 'base58').toString('base64');
  return encrypt(base58, sharedKey + password, pbkdf2_iterations);
}

function cipherFunction(password, sharedKey, pbkdf2Iterations, operation) {
  // operation can be 'enc' or 'dec'
  var id = function (msg) { return msg; };
  if (!password || !sharedKey || !pbkdf2Iterations) { return id; }
  else {
    switch(operation) {
      case 'enc':
        return function (msg) {
          return encryptSecretWithSecondPassword(msg, password, sharedKey, pbkdf2Iterations);
        };
      case 'dec':
        return function (msg) {
          return decryptSecretWithSecondPassword(msg, password, sharedKey, pbkdf2Iterations);
        };
      default:
        return id;
    };
  }
}

function decryptWallet(data, password, success, error) {
  try       { success(decryptWalletSync(data, password)); }
  catch (e) { error(e);                                   }
}

function decryptWalletSync(data, password) {
  assert(data, 'function `decryptWallet` requires encrypted wallet data');
  assert(password, 'function `decryptWallet` requires a password');

  var wrapper, version, decrypted;

  try       { wrapper = JSON.parse(data); }
  catch (e) { version = 1;                }

  if (wrapper) {
    assert(wrapper.payload, 'v2 Wallet error: missing payload');
    assert(wrapper.pbkdf2_iterations, 'v2 Wallet error: missing pbkdf2 iterations');
    assert(wrapper.version, 'v2 Wallet error: missing version');
    version = wrapper.version;
  }

  if (version > SUPPORTED_ENCRYPTION_VERSION) {
    throw 'Wallet version ' + walletVersion + ' not supported.';
  }

  try {
    // v2/v3: CBC, ISO10126, iterations in wrapper
    decrypted = decryptAes(wrapper.payload, password, wrapper.pbkdf2_iterations);
    decrypted = JSON.parse(decrypted);
  } catch (e) {
    decrypted = decryptWalletV1(data, password);
  } finally {
    assert(decrypted, 'Error decrypting wallet');
    return decrypted;
  }
}

function decryptWalletV1(data, password) {
  // Possible decryption methods for v1 wallets
  var decryptFns = [
    // v1: CBC, ISO10126, 10 iterations
    decryptAes.bind(null, data, password, 10),

    // v1: OFB, nopad, 1 iteration
    decryptAes.bind(null, data, password, 1, {
      mode    : AES.OFB,
      padding : NoPadding
    }),

    // v1: OFB, ISO7816, 1 iteration
    // ISO/IEC 9797-1 Padding method 2 is the same as ISO/IEC 7816-4:2005
    decryptAes.bind(null, data, password, 1, {
      mode    : AES.OFB,
      padding : Iso97971
    }),

    // v1: CBC, ISO10126, 1 iteration
    decryptAes.bind(null, data, password, 1, {
      mode    : AES.CBC,
      padding : Iso10126
    })
  ];

  return decryptFns.reduce(function (acc, decrypt) {
    if (acc) return acc;
    try       { return JSON.parse(decrypt()); }
    catch (e) { return null;                  }
  }, null);
}

function encryptWallet(data, password, pbkdf2_iterations, version) {
  assert(data, 'data missing');
  assert(password, 'password missing');
  assert(pbkdf2_iterations, 'pbkdf2_iterations missing');
  assert(version, 'version missing');

  return JSON.stringify({
    pbkdf2_iterations: pbkdf2_iterations,
    version: version,
    payload: encrypt(data, password, pbkdf2_iterations)
  });
}

function encrypt(data, password, iterations) {
  var SALT_BYTES  = 16
    , KEY_BIT_LEN = 256;

  var iv    = crypto.randomBytes(SALT_BYTES)
    , salt  = iv.toString('binary')
    , key   = crypto.pbkdf2Sync(password, salt, iterations, KEY_BIT_LEN / 8, 'sha1');

  var cipher = crypto.createCipheriv(AES.CBC, key, iv);
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
    , KEY_BIT_LEN = 256;

  var dataHex = new Buffer(data, 'base64').toString('hex')
    , iv      = new Buffer(dataHex.slice(0, SALT_BYTES * 2), 'hex')
    , salt    = iv.toString('binary')
    , payload = dataHex.slice(SALT_BYTES * 2)
    , key     = crypto.pbkdf2Sync(password, salt, iterations, KEY_BIT_LEN / 8, 'sha1');

  var decipher = crypto.createDecipheriv(options.mode || AES.CBC, key, iv);
  decipher.setAutoPadding(false);

  var decryptedBase64 = decipher.update(payload, 'hex', 'base64') + decipher.final('base64')
    , decryptedBytes  = new Buffer(decryptedBase64, 'base64')
    , unpaddedBytes   = (options.padding || Iso10126).unpad(decryptedBytes);

  return unpaddedBytes.toString('utf8');
}

function reencrypt(pw, sharedKey, previous_pbkdf2_iterations, new_pbkdf2_iterations) {
  assert(pw, 'password missing');
  assert(sharedKey, 'password missing');
  assert(previous_pbkdf2_iterations, 'previous_pbkdf2_iterations missing');
  assert(new_pbkdf2_iterations, 'new_pbkdf2_iterations missing');

  return function (data) {
    var decrypted = decryptSecretWithSecondPassword(data, pw, sharedKey, previous_pbkdf2_iterations);
    return encrypt(decrypted, sharedKey + pw, new_pbkdf2_iterations);
  };
}

function decryptPasswordWithProcessedPin(data, password, pbkdf2_iterations) {
  assert(data, 'data missing');
  assert(password, 'password missing');
  assert(pbkdf2_iterations, 'pbkdf2_iterations missing');
  return decryptAes(data, password, pbkdf2_iterations);
}

// Mocked for tests
function stretchPassword(password, salt, iterations) {
  return '4be158806522094dd184bc9c093ea185c6a4ec003bdc6323108e3f5eeb7e388d';
}

function hashNTimes(password, iterations) {
  var hashed = password;
  for (var i = 0; i < iterations; i++) {
    hashed = crypto.createHash('sha256').update(hashed).digest('hex');
  }
  return hashed;
}

module.exports = {
  decryptSecretWithSecondPassword: decryptSecretWithSecondPassword,
  encryptSecretWithSecondPassword: encryptSecretWithSecondPassword,
  decrypt: decryptAes,
  encrypt: encrypt,
  encryptWallet: encryptWallet,
  decryptWallet: decryptWallet,
  reencrypt: reencrypt,
  decryptPasswordWithProcessedPin: decryptPasswordWithProcessedPin,
  stretchPassword: stretchPassword,
  hashNTimes: hashNTimes,
  cipherFunction: cipherFunction,
  decryptAes: decryptAes,

  // Not part of original
  decryptWalletSync: decryptWalletSync,
  padding: {
    NoPadding: NoPadding,
    ZeroPadding: ZeroPadding,
    Iso10126: Iso10126,
    Iso97971: Iso97971
  }
};
