
var Benchmark = require('benchmark')
  , pbkdf2s   = require('../pbkdf2-samples');

var suite = new Benchmark.Suite;

var pass    = '#p%gq5EwmUtCj@Sv'
  , salt    = new Buffer('601a6fd84289bcd0121889143726dabc', 'hex')
  , iters   = 1000
  , keylen  = 256;

suite
  .add('pbkdf2s#crypto_lib', function () {
    pbkdf2s.crypto_lib(pass, salt, iters, keylen);
  })
  .add('pbkdf2s#pbkdf2_lib', function () {
    pbkdf2s.pbkdf2_lib(pass, salt, iters, keylen);
  })
  .add('pbkdf2s#sjcl_lib', function () {
    pbkdf2s.sjcl_lib(pass, salt, iters, keylen);
  })
  .on('cycle', function (event) {
    console.log(String(event.target));
  })
  .on('complete', function () {
    console.log('Fastest is ' + this.filter('fastest').map('name'));
  })
  .run({ async: true });
