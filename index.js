'use strict';

/**
 *  Experimentation with JS crypto libraries
 */

var WalletCrypto_crypto   = require('./wallet-crypto.crypto')
  , WalletCrypto_CryptoJS = require('./wallet-crypto.crypto-js');

var wallet = {
  enc : require('./data/wallet.enc.json').payload,
  dec : JSON.stringify(require('./data/wallet.dec.json'), null, 2)
};

var password  = 'testtest13'
  , iters     = 5000;

// var encrypted = WalletCrypto_crypto.encrypt(wallet.dec, password, iters);
var encrypted = WalletCrypto_CryptoJS.encrypt(wallet.dec, password, iters);
console.log(encrypted);

// var decrypted = WalletCrypto_CryptoJS.decryptAes(encrypted, password, iters);
var decrypted = WalletCrypto_crypto.decryptAes(encrypted, password, iters);
console.log(decrypted);
