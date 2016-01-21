
var WalletCrypto_crypto   = require('../wallet-crypto.crypto')
  , WalletCrypto_CryptoJS = require('../wallet-crypto.crypto-js')
  , expect                = require('chai').expect;

var wallet = {
  enc : require('../data/wallet.enc.json'),
  dec : require('../data/wallet.dec.json')
};

var walletData = JSON.stringify({
  guid: 'asdf-asdf-asdf-asdf',
  keys: {
    'asdfdsaf': 'asdfsadf',
    'asdfsad': 'asdfdsaf'
  }
}, null, 2);

describe('new wallet crypto', function () {

  var PASS = 'testtest13';
  var ITERS = 5000;

  describe('encrypt()', function () {

    it('should encrypt a wallet', function () {
      var encrypted = WalletCrypto_crypto.encrypt(walletData, PASS, ITERS);
      expect(encrypted.length).to.be.above(0);
    });

    it('should be decryptable by the old decryptAes function', function () {
      var encrypted = WalletCrypto_crypto.encrypt(walletData, PASS, ITERS);
      var decrypted = WalletCrypto_CryptoJS.decryptAes(encrypted, PASS, ITERS);
      expect(decrypted).to.equal(walletData);
    });

    it('should be decryptable by the new decryptAes function', function () {
      var encrypted = WalletCrypto_crypto.encrypt(walletData, PASS, ITERS);
      var decrypted = WalletCrypto_crypto.decryptAes(encrypted, PASS, ITERS);
      expect(decrypted).to.equal(walletData);
    });

  });

  describe('decryptAes()', function () {
    var encrypted = WalletCrypto_CryptoJS.encrypt(walletData, PASS, ITERS);

    it('should decrypt a wallet', function () {
      var decrypted = WalletCrypto_crypto.decryptAes(encrypted, PASS, ITERS);
      expect(JSON.parse(decrypted).guid).to.equal('asdf-asdf-asdf-asdf');
    });

  });

});
