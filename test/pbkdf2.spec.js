'use strict';

var pbkdf2s = require('../pbkdf2-samples')
  , expect  = require('chai').expect;

var pass    = '#p%gq5EwmUtCj@Sv'
  , salt    = new Buffer('601a6fd84289bcd0121889143726dabc', 'hex')
  , iters   = 1000
  , keySize = 256
  , result  = 'd66dd74b3511d888b28c76ae1b9c0b5814f71673fea535f0c320f582a139de36';

describe('passwordStretchers', function () {
  var crypto, pbkdf2, sjcl;

  it('should compute `crypto`', function () {
    crypto = pbkdf2s.crypto_lib(pass, salt, iters, keySize).toString('hex');
    expect(crypto).to.have.length.above(0);
  });

  it('should compute `pbkdf2`', function () {
    pbkdf2 = pbkdf2s.pbkdf2_lib(pass, salt, iters, keySize).toString();
    expect(pbkdf2).to.have.length.above(0);
  });

  it('should compute `sjcl`', function () {
    sjcl = pbkdf2s.sjcl_lib(pass, salt, iters, keySize).toString();
    expect(sjcl).to.have.length.above(0);
  });

  it('should all return the same value', function () {
    expect(crypto).to.equal(result);
    expect(pbkdf2).to.equal(result);
    expect(sjcl).to.equal(result);
  });

  it('should all return ' + keySize / 8 + ' byte strings', function () {
    expect(new Buffer(crypto, 'hex').length).to.equal(keySize / 8);
    expect(new Buffer(pbkdf2, 'hex').length).to.equal(keySize / 8);
    expect(new Buffer(sjcl, 'hex').length).to.equal(keySize / 8);
  });

});
