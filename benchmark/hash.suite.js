
var WalletCrypto_crypto   = require('../wallet-crypto.crypto')
  , WalletCrypto_CryptoJS = require('../wallet-crypto.crypto-js');

var pass  = '#p%gq5EwmUtCj@Sv'
  , iters = 5000;

suite('hash functions', function () {

  benchmark('crypto', function () {
    WalletCrypto_crypto.hashNTimes(pass, iters);
  });

  benchmark('CryptoJS', function () {
    WalletCrypto_CryptoJS.hashNTimes(pass, iters);
  });

});
