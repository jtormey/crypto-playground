
var pbkdf2s = require('../pbkdf2-samples');

var pass    = '#p%gq5EwmUtCj@Sv'
  , salt    = new Buffer('601a6fd84289bcd0121889143726dabc', 'hex')
  , iters   = 500
  , keylen  = 256;

suite('pbkdf2 implementations', function () {

  benchmark('crypto', function () {
    pbkdf2s.crypto_lib(pass, salt, iters, keylen);
  });

  benchmark('pbkdf2', function () {
    pbkdf2s.pbkdf2_lib(pass, salt, iters, keylen);
  });

  benchmark('sjcl', function () {
    pbkdf2s.sjcl_lib(pass, salt, iters, keylen);
  });

});
