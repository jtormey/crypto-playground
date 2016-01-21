
var WalletCrypto_crypto   = require('../wallet-crypto.crypto')
  , WalletCrypto_CryptoJS = require('../wallet-crypto.crypto-js')
  , expect                = require('chai').expect;

var wallet = {
  enc : require('../data/wallet.enc.json').payload,
  dec : JSON.stringify(require('../data/wallet.dec.json'), null, 2)
};

describe('new wallet crypto', function () {

  var PASS = 'testtest13';
  var ITERS = 5000;

  describe('encrypt()', function () {

    it('should encrypt a wallet', function () {
      var encrypted = WalletCrypto_crypto.encrypt(wallet.dec, PASS, ITERS);
      expect(encrypted.length).to.be.above(0);
    });

    it('should be decryptable by the old decryptAes function', function () {
      var encrypted = WalletCrypto_crypto.encrypt(wallet.dec, PASS, ITERS);
      var decrypted = WalletCrypto_CryptoJS.decryptAes(encrypted, PASS, ITERS);
      expect(decrypted).to.equal(wallet.dec);
    });

    it('should be decryptable by the new decryptAes function', function () {
      var encrypted = WalletCrypto_crypto.encrypt(wallet.dec, PASS, ITERS);
      var decrypted = WalletCrypto_crypto.decryptAes(encrypted, PASS, ITERS);
      expect(decrypted).to.equal(wallet.dec);
    });

  });

  describe('decryptAes()', function () {

    it('should decrypt a v2 wallet', function () {
      var decrypted = WalletCrypto_crypto.decryptAes(wallet.enc, PASS, ITERS);
      expect(JSON.parse(decrypted).guid).to.equal('6253e902-ce79-4027-bdc4-af51ed970eb5');
    });

  });

});
