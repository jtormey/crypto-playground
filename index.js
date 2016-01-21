'use strict';

/**
 *  Experimentation with JS crypto libraries
 */

var WalletCrypto_crypto   = require('./wallet-crypto.crypto')
  , WalletCrypto_CryptoJS = require('./wallet-crypto.crypto-js');

var wallet = {
  enc : require('./data/wallet.enc.json'),
  dec : require('./data/wallet.dec.json')
};

var password  = 'testtest13'
  , iters     = 5000;
